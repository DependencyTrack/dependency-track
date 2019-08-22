/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */

package org.dependencytrack.tasks.scanners;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import com.github.packageurl.PackageURL;
import org.dependencytrack.event.CpeAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.ComponentVersion;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.util.Convert;
import us.springett.parsers.cpe.values.LogicalValue;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Subscriber task that performs an analysis of component using internal CPE data.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public class CpeAnalysisTask extends BaseComponentAnalyzerTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(CpeAnalysisTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof CpeAnalysisEvent) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_CPE_ENABLED)) {
                return;
            }
            final CpeAnalysisEvent event = (CpeAnalysisEvent)e;
            LOGGER.info("Starting CPE analysis task");
            if (event.getComponents().size() > 0) {
                analyze(event.getComponents());
            } else {
                super.analyze();
            }
            LOGGER.info("CPE analysis complete");
        }
    }

    /**
     * Determines if the {@link CpeAnalysisTask} is suitable for analysis based on the PackageURL.
     *
     * @param purl the PackageURL to analyze
     * @return true if CpeAnalysisTask should analyze, false if not
     */
    public boolean shouldAnalyze(final PackageURL purl) {
        return true;
    }

    /**
     * Analyzes a list of Components.
     * @param components a list of Components
     */
    public void analyze(final List<Component> components) {
        final boolean fuzzyEnabled = super.isEnabled(ConfigPropertyConstants.SCANNER_CPE_FUZZY_ENABLED);
        final boolean excludeComponentsWithPurl = super.isEnabled(ConfigPropertyConstants.SCANNER_CPE_FUZZY_EXCLUDE_PURL);
        try (QueryManager qm = new QueryManager()) {
            for (Component component : components) {
                versionRangeAnalysis(qm, component);
                if (fuzzyEnabled) {
                    if (component.getPurl() == null || !excludeComponentsWithPurl) {
                        fuzzyCpeAnalysis(qm, component);
                    }
                }
            }
        }
    }

    private void versionRangeAnalysis(final QueryManager qm, final Component component) {
        if (component.getCpe() != null) {
            try {
                final us.springett.parsers.cpe.Cpe parsedCpe = CpeParser.parse(component.getCpe());
                final List<VulnerableSoftware> matchedCpes = qm.getAllVulnerableSoftware(
                        parsedCpe.getPart().getAbbreviation(),
                        parsedCpe.getVendor(),
                        parsedCpe.getProduct());
                for (VulnerableSoftware vs: matchedCpes) {
                    if (compareVersions(vs, parsedCpe.getVersion())) {
                        if (vs.getVulnerabilities() != null) {
                            for (Vulnerability vulnerability : vs.getVulnerabilities()) {
                                qm.addVulnerability(vulnerability, component);
                            }
                        }
                    }
                }
            } catch (CpeParsingException e) {
                LOGGER.error("An error occurred parsing a CPE defined for a component: " + component.getCpe(), e);
            }
        }
    }

    /**
     * Evaluates the target against the version and version range checks:
     * versionEndExcluding, versionStartExcluding versionEndIncluding, and
     * versionStartIncluding.
     *
     * @param vs a reference to the vulnerable software to compare
     * @param targetVersion the version to compare
     * @return <code>true</code> if the target version is matched; otherwise
     * <code>false</code>
     */
    private static boolean compareVersions(VulnerableSoftware vs, String targetVersion) {
        if (LogicalValue.NA.getAbbreviation().equals(vs.getVersion())) {
            return false;
        }
        //if any of the four conditions will be evaluated - then true;
        boolean result = (vs.getVersionEndExcluding() != null && !vs.getVersionEndExcluding().isEmpty())
                || (vs.getVersionStartExcluding() != null && !vs.getVersionStartExcluding().isEmpty())
                || (vs.getVersionEndIncluding() != null && !vs.getVersionEndIncluding().isEmpty())
                || (vs.getVersionStartIncluding() != null && !vs.getVersionStartIncluding().isEmpty());

        if (!result && compareAttributes(vs.getVersion(), targetVersion)) {
            return true;
        }

        final ComponentVersion target = new ComponentVersion(targetVersion);
        if (target.getVersionParts().isEmpty()) {
            return false;
        }
        if (result && vs.getVersionEndExcluding() != null && !vs.getVersionEndExcluding().isEmpty()) {
            final ComponentVersion endExcluding = new ComponentVersion(vs.getVersionEndExcluding());
            result = endExcluding.compareTo(target) > 0;
        }
        if (result && vs.getVersionStartExcluding() != null && !vs.getVersionStartExcluding().isEmpty()) {
            final ComponentVersion startExcluding = new ComponentVersion(vs.getVersionStartExcluding());
            result = startExcluding.compareTo(target) < 0;
        }
        if (result && vs.getVersionEndIncluding() != null && !vs.getVersionEndIncluding().isEmpty()) {
            final ComponentVersion endIncluding = new ComponentVersion(vs.getVersionEndIncluding());
            result &= endIncluding.compareTo(target) >= 0;
        }
        if (result && vs.getVersionStartIncluding() != null && !vs.getVersionStartIncluding().isEmpty()) {
            final ComponentVersion startIncluding = new ComponentVersion(vs.getVersionStartIncluding());
            result &= startIncluding.compareTo(target) <= 0;
        }
        return result;
    }

    /**
     * This does not follow the spec precisely because ANY compared to NA is
     * classified as undefined by the spec; however, in this implementation ANY
     * will match NA and return true.
     *
     * This will compare the left value to the right value and return true if
     * the left matches the right. Note that it is possible that the right would
     * not match the left value.
     *
     * @param left the left value to compare
     * @param right the right value to compare
     * @return <code>true</code> if the left value matches the right value;
     * otherwise <code>false</code>
     */
    private static boolean compareAttributes(String left, String right) {
        //the numbers below come from the CPE Matching standard
        //Table 6-2: Enumeration of Attribute Comparison Set Relations
        //https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf

        if (left.equalsIgnoreCase(right)) {
            //1 6 9
            return true;
        } else if (LogicalValue.ANY.getAbbreviation().equals(left)) {
            //2 3 4
            return true;
        } else if (LogicalValue.NA.getAbbreviation().equals(left)) {
            //5 7 8
            return false;
        } else if (LogicalValue.NA.getAbbreviation().equals(right)) {
            //12 16
            return false;
        } else if (LogicalValue.ANY.getAbbreviation().equals(right)) {
            //13 15
            return false;
        }
        //10 11 14 17
        if (containsSpecialCharacter(left)) {
            Pattern p = Convert.wellFormedToPattern(left.toLowerCase());
            Matcher m = p.matcher(right.toLowerCase());
            return m.matches();
        }
        return false;
    }

    /**
     * Determines if the string has an unquoted special character.
     *
     * @param value the string to check
     * @return <code>true</code> if the string contains an unquoted special
     * character; otherwise <code>false</code>
     */
    private static boolean containsSpecialCharacter(String value) {
        for (int x = 0; x < value.length(); x++) {
            char c = value.charAt(x);
            if (c == '?' || c == '*') {
                return true;
            } else if (c == '\\') {
                //skip the next character because it is quoted
                x += 1;
            }
        }
        return false;
    }

    private void fuzzyCpeAnalysis(final QueryManager qm, final Component component) {
        //TODO
    }
}
