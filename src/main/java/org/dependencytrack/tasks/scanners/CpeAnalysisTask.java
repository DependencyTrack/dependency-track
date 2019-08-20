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
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import java.util.List;

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
                preciseCpeAnalysis(qm, component);
                cpeFieldAnalysis(qm, component);
                if (fuzzyEnabled) {
                    if (component.getPurl() == null || !excludeComponentsWithPurl) {
                        fuzzyCpeAnalysis(qm, component);
                    }
                }
            }
        }
    }

    /**
     * This method will analyze the CPE field specified in a component and match it with
     * CPEs that are known to contain vulnerabilities. Supports both CPE 2.2 and CPE 2.3 URIs.
     */
    private void preciseCpeAnalysis(final QueryManager qm, final Component component) {
        if (component.getCpe() != null) {
            final List<VulnerableSoftware> matchedCpes = qm.getAllVulnerableSoftwareByCpe(component.getCpe());
            for (VulnerableSoftware vs: matchedCpes) {
                if (vs.getVulnerabilities() != null) {
                    for (Vulnerability vulnerability: vs.getVulnerabilities()) {
                        qm.addVulnerability(vulnerability, component);
                    }
                }
            }
        }
    }

    /**
     * This method will analyze the CPE field specified in a component by parsing the CPE
     * into the various fields (part, vendor, product, version) and match it with CPEs that
     * are known to contain vulnerabilities.
     */
    private void cpeFieldAnalysis(final QueryManager qm, final Component component) {
        if (component.getCpe() != null) {
            try {
                final us.springett.parsers.cpe.Cpe parsedCpe = CpeParser.parse(component.getCpe());
                final List<VulnerableSoftware> matchedCpes = qm.getAllVulnerableSoftware(
                        parsedCpe.getPart().getAbbreviation(),
                        parsedCpe.getVendor(),
                        parsedCpe.getProduct(),
                        parsedCpe.getVersion());
                for (VulnerableSoftware vs: matchedCpes) {
                    if (vs.getVulnerabilities() != null) {
                        for (Vulnerability vulnerability: vs.getVulnerabilities()) {
                            qm.addVulnerability(vulnerability, component);
                        }
                    }
                }
            } catch (CpeParsingException e) {
                LOGGER.error("An error occurred parsing a CPE defined for a component: " + component.getCpe(), e);
            }
        }
    }

    private void fuzzyCpeAnalysis(final QueryManager qm, final Component component) {
        //TODO
    }
}
