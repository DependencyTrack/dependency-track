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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.tasks.scanners;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import org.dependencytrack.util.VulnerableSoftwareMatchUtil;
import us.springett.parsers.cpe.Cpe;
import java.util.List;

/**
 * Base analysis task for using the internal VulnerableSoftware model as the source of truth for
 * vulnerability intelligence.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public abstract class AbstractVulnerableSoftwareAnalysisTask extends BaseComponentAnalyzerTask {

    /**
     * Analyzes the targetVersion against a list of VulnerableSoftware objects which may contain
     * specific versions or version ranges. For every match, every vulnerability associated with
     * the VulnerableSoftware object will be applied to the specified component.
     *
     * @param qm            the QueryManager to use
     * @param vsList        a list of VulnerableSoftware objects
     * @param targetVersion the version of the component
     * @param component     the component being analyzed
     */
    protected void analyzeVersionRange(final QueryManager qm, final List<VulnerableSoftware> vsList,
                                       final Cpe targetCpe, final String targetVersion, final Component component,
                                       final VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel) {
        for (final VulnerableSoftware vs : vsList) {
            final Boolean isCpeMatch = VulnerableSoftwareMatchUtil.maybeMatchCpe(vs, targetCpe, targetVersion);
            if ((isCpeMatch == null || isCpeMatch) && VulnerableSoftwareMatchUtil.compareVersions(vs, targetVersion)) {
                if (vs.getVulnerabilities() != null) {
                    for (final Vulnerability vulnerability : vs.getVulnerabilities()) {
                        NotificationUtil.analyzeNotificationCriteria(qm, vulnerability, component, vulnerabilityAnalysisLevel);
                        qm.addVulnerability(vulnerability, component, this.getAnalyzerIdentity());
                    }
                }
            }
        }
    }
}
