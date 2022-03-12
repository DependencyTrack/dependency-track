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
import org.dependencytrack.search.SearchManager;
import org.dependencytrack.search.SearchResult;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
        final boolean fuzzyEnabled = super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_ENABLED);
        us.springett.parsers.cpe.Cpe parsedCpe = null;
        if (component.getCpe() != null) {
            try {
                parsedCpe = CpeParser.parse(component.getCpe());
            } catch (CpeParsingException e) {
                LOGGER.warn("An error occurred while parsing: " + component.getCpe() + " - The CPE is invalid and will be discarded. " + e.getMessage());
            }
        }
        List<VulnerableSoftware>  fuzzyList = Collections.emptyList();
        if (fuzzyEnabled) {
            fuzzyList = fuzzyAnalysis(qm, component);
        }
        if (parsedCpe != null) {
            final List<VulnerableSoftware> vsList = qm.getAllVulnerableSoftware(parsedCpe.getPart().getAbbreviation(), parsedCpe.getVendor(), parsedCpe.getProduct(), component.getPurl());
            super.analyzeVersionRange(qm, Stream.concat(vsList.stream(), fuzzyList.stream()).collect(Collectors.toList()), parsedCpe.getVersion(), parsedCpe.getUpdate(), component);
        } else {
            final List<VulnerableSoftware> vsList = qm.getAllVulnerableSoftware(null, null, null, component.getPurl());
            super.analyzeVersionRange(qm, Stream.concat(vsList.stream(), fuzzyList.stream()).collect(Collectors.toList()), component.getPurl().getVersion(), null, component);
        }
    }

    private List<VulnerableSoftware> fuzzyAnalysis(QueryManager qm, final Component component) {
        final boolean excludeComponentsWithPurl = super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_EXCLUDE_PURL);
        List<VulnerableSoftware>  fuzzyList = new LinkedList<>();
        if (component.getPurl() == null || !excludeComponentsWithPurl) {
            SearchManager sm = new SearchManager();
            //The tilde makes it fuzzy. e.g. Will match libexpat1 to libexpat and product exact matches with vendor mismatch
            SearchResult sr = sm.searchVulnerableSoftwareIndex("product:" + component.getName() + "~");
            if (sr.getResults().containsKey("vulnerablesoftware")) {
                for (Map<String, String> result : sr.getResults().get("vulnerablesoftware")) {
                    fuzzyList.add(qm.getObjectByUuid(VulnerableSoftware.class, result.get("uuid")));
                }
            }
        }
        return fuzzyList;
    }
}
