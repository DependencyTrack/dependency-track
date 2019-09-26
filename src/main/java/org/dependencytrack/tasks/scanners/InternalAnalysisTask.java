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
import org.dependencytrack.event.InternalAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import java.util.List;

/**
 * Subscriber task that performs an analysis of component using internal CPE/PURL data.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public class InternalAnalysisTask extends AbstractVulnerableSoftwareAnalysisTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(InternalAnalysisTask.class);

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
            } else {
                super.analyze();
            }
            LOGGER.info("Internal analysis complete");
        }
    }

    /**
     * Determines if the {@link InternalAnalysisTask} is suitable for analysis based on the PackageURL.
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
        final boolean fuzzyEnabled = super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_ENABLED);
        final boolean excludeComponentsWithPurl = super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_EXCLUDE_PURL);
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
                super.analyzeVersionRange(qm, matchedCpes, parsedCpe.getVersion(), component);
            } catch (CpeParsingException e) {
                LOGGER.error("An error occurred parsing a CPE defined for a component: " + component.getCpe(), e);
            }
        }
    }

    private void fuzzyCpeAnalysis(final QueryManager qm, final Component component) {
        //TODO
    }
}
