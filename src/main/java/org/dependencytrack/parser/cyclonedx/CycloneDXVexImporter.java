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
package org.dependencytrack.parser.cyclonedx;

import alpine.common.logging.Logger;
import org.apache.commons.collections4.CollectionUtils;
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

import java.util.ArrayList;
import java.util.List;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.trimToNull;

public class CycloneDXVexImporter {

    private static final Logger LOGGER = Logger.getLogger(CycloneDXVexImporter.class);

    private static final String COMMENTER = "CycloneDX VEX";

    public void applyVex(final QueryManager qm, final Bom bom, final Project project) {
        if (bom.getVulnerabilities() == null || bom.getVulnerabilities().isEmpty()) {
            LOGGER.info("The uploaded VEX does not contain any vulnerabilities; Skipping VEX import");
            return;
        }
        if (qm.getVulnerabilityCount(project, true) == 0) {
            LOGGER.info("The project %s does not have any vulnerabilities; Skipping VEX import".formatted(project));
            return;
        }

        final List<org.cyclonedx.model.vulnerability.Vulnerability> vexVulns = getApplicableVexVulnerabilities(bom.getVulnerabilities());
        if (vexVulns.isEmpty()) {
            LOGGER.info("The uploaded VEX does not contain any applicable vulnerabilities; Skipping VEX import");
            return;
        }

        for (final org.cyclonedx.model.vulnerability.Vulnerability vexVuln : vexVulns) {
            final Vulnerability dtVuln = qm.getVulnerabilityByVulnId(vexVuln.getSource().getName(), vexVuln.getId());
            if (dtVuln == null) {
                LOGGER.warn("""
                        VEX contains analysis for vulnerability %s/%s, but the project is not affected by it. \
                        Analyses can currently only be applied to existing findings.\
                        """.formatted(vexVuln.getSource().getName(), vexVuln.getId()));
                continue;
            }

            for (org.cyclonedx.model.vulnerability.Vulnerability.Affect affect : vexVuln.getAffects()) {
                final ObjectLocator ol = new ObjectLocator(bom, affect.getRef()).locate();
                if ((ol.found() && ol.isMetadataComponent()) || (!ol.found() && BomLink.isBomLink(affect.getRef()))) {
                    // Affects the project itself
                    List<Component> components = qm.getAllVulnerableComponents(project, dtVuln, true);
                    for (final Component component : components) {
                        updateAnalysis(qm, component, dtVuln, vexVuln);
                    }
                } else if (ol.found() && ol.isComponent()) {
                    // Affects an individual component
                    final org.cyclonedx.model.Component cdxComponent = (org.cyclonedx.model.Component) ol.getObject();
                    final ComponentIdentity cid = new ComponentIdentity(cdxComponent);
                    List<Component> components = qm.matchIdentity(project, cid);
                    for (final Component component : components) {
                        updateAnalysis(qm, component, dtVuln, vexVuln);
                    }
                } else if (ol.found() && ol.isService()) {
                    // Affects an individual service
                    // TODO add VEX support for services
                } else {
                    LOGGER.warn("""
                            Unable to locate affected element (metadata.component, components[].component, \
                            or services[].service) based on the BOM reference %s. The vulnerability.affects[].ref \
                            node of %s/%s is not resolvable; Skipping it\
                            """.formatted(affect.getRef(), vexVuln.getSource().getName(), vexVuln.getId()));
                }
            }
        }
    }

    private static List<org.cyclonedx.model.vulnerability.Vulnerability> getApplicableVexVulnerabilities(
            final List<org.cyclonedx.model.vulnerability.Vulnerability> vexVulns) {
        final var applicableVulns = new ArrayList<org.cyclonedx.model.vulnerability.Vulnerability>();
        for (final var vexVuln : vexVulns) {
            final int vexVulnPos = vexVulns.indexOf(vexVuln);
            if (isBlank(vexVuln.getId()) || vexVuln.getSource() == null || isBlank(vexVuln.getSource().getName())) {
                LOGGER.warn("VEX vulnerability at position #%d does not have an ID and / or source; Skipping it".formatted(vexVulnPos));
                continue;
            }

            final String vexVulnId = vexVuln.getId();
            final String vexVulnSource = vexVuln.getSource().getName();
            if (!Vulnerability.Source.isKnownSource(vexVuln.getSource().getName())) {
                LOGGER.warn("VEX vulnerability %s/%s at position #%d is from an unsupported source; Skipping it"
                        .formatted(vexVulnSource, vexVulnId, vexVulnPos));
                continue;
            }
            if (CollectionUtils.isEmpty(vexVuln.getAffects())) {
                LOGGER.debug("VEX vulnerability %s/%s at position #%d does not have an affects node; Skipping it"
                        .formatted(vexVulnSource, vexVulnId, vexVulnPos));
                continue;
            }
            if (vexVuln.getAnalysis() == null) {
                LOGGER.debug("VEX vulnerability %s/%s at position #%d does not have an analysis; Skipping it"
                        .formatted(vexVulnSource, vexVulnId, vexVulnPos));
                continue;
            }

            applicableVulns.add(vexVuln);
        }

        return applicableVulns;
    }

    private static void updateAnalysis(final QueryManager qm, final Component component, final Vulnerability vuln,
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
        if (trimToNull(cdxVuln.getAnalysis().getDetail()) != null) {
            analysisDetails = cdxVuln.getAnalysis().getDetail().trim();
            AnalysisCommentUtil.makeAnalysisDetailsComment(qm, analysis, cdxVuln.getAnalysis().getDetail().trim(), COMMENTER);
        }
        if (cdxVuln.getAnalysis().getResponses() != null) {
            for (org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response cdxRes : cdxVuln.getAnalysis().getResponses()) {
                analysisResponse = ModelConverter.convertCdxVulnAnalysisResponseToDtAnalysisResponse(cdxRes);
                AnalysisCommentUtil.makeAnalysisResponseComment(qm, analysis, analysisResponse, COMMENTER);
            }
        }
        qm.makeAnalysis(component, refreshedVuln, analysisState, analysisJustification, analysisResponse, analysisDetails, suppress);
    }
}
