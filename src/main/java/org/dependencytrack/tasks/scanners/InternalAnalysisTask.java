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

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.InternalAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.search.FuzzyVulnerableSoftwareSearchManager;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.Collections;
import java.util.List;

/**
 * Subscriber task that performs an analysis of component using internal CPE/PURL data.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public class InternalAnalysisTask extends AbstractVulnerableSoftwareAnalysisTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(InternalAnalysisTask.class);

    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.INTERNAL_ANALYZER;
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof InternalAnalysisEvent) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED)) {
                return;
            }
            final InternalAnalysisEvent event = (InternalAnalysisEvent)e;
            LOGGER.info("Starting internal analysis task");
            if (event.getComponents().size() > 0) {
                analyze(event.getComponents());
            }
            LOGGER.info("Internal analysis complete");
        }
    }

    /**
     * Determines if the {@link InternalAnalysisTask} is capable of analyzing the specified Component.
     *
     * @param component the Component to analyze
     * @return true if InternalAnalysisTask should analyze, false if not
     */
    public boolean isCapable(final Component component) {
        return component.getCpe() != null || component.getPurl() != null;
    }

    /**
     * Analyzes a list of Components.
     * @param components a list of Components
     */
    public void analyze(final List<Component> components) {
        try (QueryManager qm = new QueryManager()) {
            for (final Component c : components) {
                final Component component = qm.getObjectByUuid(Component.class, c.getUuid()); // Refresh component and attach to current pm.
                if (component == null) continue;
                versionRangeAnalysis(qm, component);
            }
        }
    }

    private void versionRangeAnalysis(final QueryManager qm, final Component component) {
        final boolean fuzzyEnabled = super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_ENABLED) &&
                (!component.isInternal() || !super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_EXCLUDE_INTERNAL));
        final boolean excludeComponentsWithPurl = super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_EXCLUDE_PURL);
        us.springett.parsers.cpe.Cpe parsedCpe = null;
        if (component.getCpe() != null) {
            try {
                parsedCpe = CpeParser.parse(component.getCpe());
            } catch (CpeParsingException e) {
                LOGGER.warn("An error occurred while parsing: " + component.getCpe() + " - The CPE is invalid and will be discarded. " + e.getMessage());
            }
        }
        List<VulnerableSoftware> vsList = Collections.emptyList();
        String componentVersion;
        String componentUpdate;
        if (parsedCpe != null) {
            componentVersion = parsedCpe.getVersion();
            componentUpdate = parsedCpe.getUpdate();
        } else if (component.getPurl() != null) {
            componentVersion = component.getPurl().getVersion();
            componentUpdate = null;
        } else {
            // Catch cases where the CPE couldn't be parsed and no PURL exists.
            // Should be rare, but could lead to NPEs later.
            LOGGER.debug("Neither CPE nor PURL of component " + component.getUuid() + " provide a version - skipping analysis");
            return;
        }
        // In some cases, componentVersion may be null, such as when a Package URL does not have a version specified
        if (componentVersion == null) {
            return;
        }
        // https://github.com/DependencyTrack/dependency-track/issues/1574
        // Some ecosystems use the "v" version prefix (e.g. v1.2.3) for their components.
        // However, both the NVD and GHSA store versions without that prefix.
        // For this reason, the prefix is stripped before running analyzeVersionRange.
        //
        // REVISIT THIS WHEN ADDING NEW VULNERABILITY SOURCES!
        if (componentVersion.length() > 1 && componentVersion.startsWith("v")) {
            if (componentVersion.matches("v0.0.0-\\d{14}-[a-f0-9]{12}")) {
                componentVersion = componentVersion.substring(7,11) + "-" + componentVersion.substring(11,13) + "-" + componentVersion.substring(13,15);
            } else {
                componentVersion = componentVersion.substring(1);
            }
        }

        if (parsedCpe != null) {
            vsList = qm.getAllVulnerableSoftware(parsedCpe.getPart().getAbbreviation(), parsedCpe.getVendor(), parsedCpe.getProduct(), component.getPurl());
        } else {
            vsList = qm.getAllVulnerableSoftware(null, null, null, component.getPurl());
        }

        if (fuzzyEnabled && vsList.isEmpty()) {
            FuzzyVulnerableSoftwareSearchManager fm = new FuzzyVulnerableSoftwareSearchManager(excludeComponentsWithPurl);
            vsList = fm.fuzzyAnalysis(qm, component, parsedCpe);
        }
        super.analyzeVersionRange(qm, vsList, componentVersion, componentUpdate, component);
    }

}
