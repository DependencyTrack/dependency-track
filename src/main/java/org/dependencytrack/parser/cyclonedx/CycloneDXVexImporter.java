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
package org.dependencytrack.parser.cyclonedx;

import alpine.common.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.model.Bom;
import org.cyclonedx.util.BomLink;
import org.cyclonedx.util.ObjectLocator;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.AnalysisCommentUtil;

import java.util.List;

public class CycloneDXVexImporter {

    private static final Logger LOGGER = Logger.getLogger(CycloneDXVexImporter.class);

    private static final String COMMENTER = "CycloneDX VEX";

    public void applyVex(final QueryManager qm, final Bom bom, final Project project) {
        if (bom.getVulnerabilities() == null) return;
        List<org.cyclonedx.model.vulnerability.Vulnerability> auditableVulnerabilities = bom.getVulnerabilities().stream().filter(
                bomVuln -> bomVuln.getSource() == null || Vulnerability.Source.isKnownSource(bomVuln.getSource().getName())
        ).toList();
        for (org.cyclonedx.model.vulnerability.Vulnerability cdxVuln: auditableVulnerabilities) {
            if (cdxVuln.getAnalysis() == null) continue;
            final List<Vulnerability> vulns = qm.getVulnerabilities(project, true);
            if (vulns == null) continue;
            for (final Vulnerability vuln: vulns) {
                // NOTE: These vulnerability objects are detached
                if (shouldAuditVulnerability(cdxVuln, vuln)) {

                    if (cdxVuln.getAffects() == null) continue;
                    for (org.cyclonedx.model.vulnerability.Vulnerability.Affect affect: cdxVuln.getAffects()) {
                        final ObjectLocator ol = new ObjectLocator(bom, affect.getRef()).locate();
                        if ((ol.found() && ol.isMetadataComponent()) || (!ol.found() && BomLink.isBomLink(affect.getRef()))) {
                            // Affects the project itself
                            List<Component> components = qm.getAllVulnerableComponents(project, vuln, true);
                            for (final Component component: components) {
                                updateAnalysis(qm, component, vuln, cdxVuln);
                            }
                        } else if (ol.found() && ol.isComponent()) {
                            // Affects an individual component
                            final org.cyclonedx.model.Component cdxComponent = (org.cyclonedx.model.Component)ol.getObject();
                            final ComponentIdentity cid = new ComponentIdentity(cdxComponent);
                            List<Component> components = qm.matchIdentity(project, cid);
                            for (final Component component: components) {
                                updateAnalysis(qm, component, vuln, cdxVuln);
                            }
                        } else if (ol.found() && ol.isService()) {
                            // Affects an individual service
                            // TODO add VEX support for services
                        }
                    }
                } else {
                    LOGGER.warn("Analysis data for vulnerability "+cdxVuln.getId()+" will be ignored because either the source is missing or there is a source/vulnid mismatch between VEX and Dependency Track database.");
                }
            }
        }
    }

    private boolean shouldAuditVulnerability(org.cyclonedx.model.vulnerability.Vulnerability bomVulnerability, Vulnerability dtVulnerability) {
        boolean result = true;
        result = result && bomVulnerability.getSource() != null;
        result = result && dtVulnerability.getVulnId().equals(bomVulnerability.getId());
        result = result && dtVulnerability.getSource().equalsIgnoreCase(bomVulnerability.getSource().getName());
        return result;
    }

    private void updateAnalysis(final QueryManager qm, final Component component, final Vulnerability vuln,
                                final org.cyclonedx.model.vulnerability.Vulnerability cdxVuln) {
        // The vulnerability object is detached, so refresh it.
        final Vulnerability refreshedVuln = qm.getObjectByUuid(Vulnerability.class, vuln.getUuid());
        Analysis analysis = qm.getAnalysis(component, refreshedVuln);
        AnalysisState analysisState = null;
        AnalysisJustification analysisJustification = null;
        String analysisDetails = null;
        AnalysisResponse analysisResponse = null;
        boolean suppress = false;
        if (analysis == null) {
            analysis = qm.makeAnalysis(component, refreshedVuln, AnalysisState.NOT_SET, null, null, null, null);
        }
        if (cdxVuln.getAnalysis().getState() != null) {
            analysisState = ModelConverter.convertCdxVulnAnalysisStateToDtAnalysisState(cdxVuln.getAnalysis().getState());
            suppress = (AnalysisState.FALSE_POSITIVE == analysisState || AnalysisState.NOT_AFFECTED == analysisState || AnalysisState.RESOLVED == analysisState);
            AnalysisCommentUtil.makeStateComment(qm, analysis, analysisState, COMMENTER);
        }
        if (cdxVuln.getAnalysis().getJustification() != null) {
            analysisJustification = ModelConverter.convertCdxVulnAnalysisJustificationToDtAnalysisJustification(cdxVuln.getAnalysis().getJustification());
            AnalysisCommentUtil.makeJustificationComment(qm, analysis, analysisJustification, COMMENTER);
        }
        if (StringUtils.trimToNull(cdxVuln.getAnalysis().getDetail()) != null) {
            analysisDetails = cdxVuln.getAnalysis().getDetail().trim();
            AnalysisCommentUtil.makeAnalysisDetailsComment(qm, analysis, cdxVuln.getAnalysis().getDetail().trim(), COMMENTER);
        }
        if (cdxVuln.getAnalysis().getResponses() != null) {
            for (org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response cdxRes: cdxVuln.getAnalysis().getResponses()) {
                analysisResponse = ModelConverter.convertCdxVulnAnalysisResponseToDtAnalysisResponse(cdxRes);
                AnalysisCommentUtil.makeAnalysisResponseComment(qm, analysis, analysisResponse, COMMENTER);
            }
        }
        analysis = qm.makeAnalysis(component, refreshedVuln, analysisState, analysisJustification, analysisResponse, analysisDetails, suppress);
    }
}
