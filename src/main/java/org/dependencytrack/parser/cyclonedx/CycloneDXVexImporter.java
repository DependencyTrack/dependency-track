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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.util.Objects.requireNonNullElse;
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

        final List<org.cyclonedx.model.vulnerability.Vulnerability> vexVulns = getApplicableVexVulnerabilities(bom.getVulnerabilities());
        if (vexVulns.isEmpty()) {
            LOGGER.info("The uploaded VEX does not contain any applicable vulnerabilities; Skipping VEX import");
            return;
        }

        if (!qm.hasVulnerabilities(project)) {
            LOGGER.info("The project %s does not have any vulnerabilities; Skipping VEX import".formatted(project));
            return;
        }

        final Map<String, BomRefTarget> targetByBomRef = indexComponents(bom);
        final Map<String, List<Component>> componentsByBomRef = new HashMap<>();

        for (final org.cyclonedx.model.vulnerability.Vulnerability vexVuln : vexVulns) {
            final Vulnerability dtVuln = qm.getVulnerabilityByVulnId(vexVuln.getSource().getName(), vexVuln.getId());
            if (dtVuln == null) {
                LOGGER.warn("""
                        VEX contains analysis for vulnerability %s/%s, but the project is not affected by it. \
                        Analyses can currently only be applied to existing findings.\
                        """.formatted(vexVuln.getSource().getName(), vexVuln.getId()));
                continue;
            }

            List<Component> vulnerableComponents = null;

            for (org.cyclonedx.model.vulnerability.Vulnerability.Affect affect : vexVuln.getAffects()) {
                final String affectedBomRef = affect.getRef();
                final BomRefTarget affectedBomRefTarget = affectedBomRef != null
                        ? targetByBomRef.get(affectedBomRef)
                        : null;

                final boolean isProjectScoped =
                        (affectedBomRefTarget != null && affectedBomRefTarget.isMetadataComponent())
                                || (affectedBomRefTarget == null && affectedBomRef != null && BomLink.isBomLink(affectedBomRef));

                if (isProjectScoped) {
                    if (vulnerableComponents == null) {
                        vulnerableComponents = qm.getAllVulnerableComponents(project, dtVuln);
                    }
                    for (final Component component : vulnerableComponents) {
                        updateAnalysis(qm, component, dtVuln, vexVuln);
                    }
                } else if (affectedBomRefTarget != null) {
                    final List<Component> components = componentsByBomRef.computeIfAbsent(affectedBomRef, ignored -> {
                        final var cid = new ComponentIdentity(affectedBomRefTarget.component());
                        return qm.matchIdentity(project, cid);
                    });
                    for (final Component component : components) {
                        updateAnalysis(qm, component, dtVuln, vexVuln);
                    }
                } else {
                    LOGGER.warn("""
                            Unable to locate affected element (metadata.component or components[].component) \
                            based on the BOM reference %s. The vulnerability.affects[].ref \
                            node of %s/%s is not resolvable; Skipping it\
                            """.formatted(affectedBomRef, vexVuln.getSource().getName(), vexVuln.getId()));
                }
            }
        }
    }

    private static List<org.cyclonedx.model.vulnerability.Vulnerability> getApplicableVexVulnerabilities(
            final List<org.cyclonedx.model.vulnerability.Vulnerability> vexVulns) {
        final var applicableVulns = new ArrayList<org.cyclonedx.model.vulnerability.Vulnerability>();
        for (int vexVulnPos = 0; vexVulnPos < vexVulns.size(); vexVulnPos++) {
            final var vexVuln = vexVulns.get(vexVulnPos);
            if (isBlank(vexVuln.getId()) || vexVuln.getSource() == null || isBlank(vexVuln.getSource().getName())) {
                LOGGER.warn("VEX vulnerability at position #%d does not have an ID and / or source; Skipping it".formatted(vexVulnPos));
                continue;
            }

            final String vexVulnId = vexVuln.getId();
            final String vexVulnSource = vexVuln.getSource().getName();
            if (!Vulnerability.Source.isKnownSource(vexVulnSource)) {
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

    private record BomRefTarget(org.cyclonedx.model.Component component, boolean isMetadataComponent) {
    }

    private static Map<String, BomRefTarget> indexComponents(Bom bom) {
        final Map<String, BomRefTarget> targetByBomRef = new HashMap<>();
        if (bom == null) {
            return targetByBomRef;
        }

        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            indexComponents(List.of(bom.getMetadata().getComponent()), targetByBomRef, true);
        }

        indexComponents(bom.getComponents(), targetByBomRef, false);
        return targetByBomRef;
    }

    private static void indexComponents(
            List<org.cyclonedx.model.Component> components,
            Map<String, BomRefTarget> targetByBomRef,
            boolean metadataComponent) {
        if (components == null) {
            return;
        }

        for (final var component : components) {
            if (component.getBomRef() != null) {
                targetByBomRef.putIfAbsent(
                        component.getBomRef(),
                        new BomRefTarget(component, metadataComponent));
            }

            if (component.getComponents() != null && !component.getComponents().isEmpty()) {
                indexComponents(component.getComponents(), targetByBomRef, false);
            }
        }
    }

    private static void updateAnalysis(final QueryManager qm, final Component component, final Vulnerability dtVuln,
                                       final org.cyclonedx.model.vulnerability.Vulnerability cdxVuln) {
        final org.cyclonedx.model.vulnerability.Vulnerability.Analysis cdxAnalysis = cdxVuln.getAnalysis();

        final Analysis existing = qm.getAnalysis(component, dtVuln);
        final AnalysisState oldState = existing != null
                ? requireNonNullElse(existing.getAnalysisState(), AnalysisState.NOT_SET)
                : AnalysisState.NOT_SET;
        final AnalysisJustification oldJustification = existing != null
                ? requireNonNullElse(existing.getAnalysisJustification(), AnalysisJustification.NOT_SET)
                : AnalysisJustification.NOT_SET;
        final AnalysisResponse oldResponse = existing != null
                ? requireNonNullElse(existing.getAnalysisResponse(), AnalysisResponse.NOT_SET)
                : AnalysisResponse.NOT_SET;
        final String oldDetails = existing != null
                ? requireNonNullElse(existing.getAnalysisDetails(), "")
                : "";

        AnalysisState newState = null;
        boolean suppress = false;
        if (cdxAnalysis.getState() != null) {
            newState = ModelConverter.convertCdxVulnAnalysisStateToDtAnalysisState(cdxAnalysis.getState());
            suppress = AnalysisState.FALSE_POSITIVE == newState
                    || AnalysisState.NOT_AFFECTED == newState
                    || AnalysisState.RESOLVED == newState;
        }

        AnalysisJustification newJustification = null;
        if (cdxAnalysis.getJustification() != null) {
            newJustification = ModelConverter.convertCdxVulnAnalysisJustificationToDtAnalysisJustification(cdxAnalysis.getJustification());
        }

        String newDetails = null;
        if (trimToNull(cdxAnalysis.getDetail()) != null) {
            newDetails = cdxAnalysis.getDetail().trim();
        }

        AnalysisResponse newResponse = null;
        final List<AnalysisResponse> responseTrail;
        if (cdxAnalysis.getResponses() != null && !cdxAnalysis.getResponses().isEmpty()) {
            responseTrail = new ArrayList<>(cdxAnalysis.getResponses().size());
            for (var cdxRes : cdxAnalysis.getResponses()) {
                final AnalysisResponse response = ModelConverter.convertCdxVulnAnalysisResponseToDtAnalysisResponse(cdxRes);
                responseTrail.add(response);
                newResponse = response;
            }
        } else {
            responseTrail = Collections.emptyList();
        }

        final Analysis updated;
        if (existing != null) {
            updated = qm.updateAnalysis(existing, newState, newJustification, newResponse, newDetails, suppress);
        } else {
            final AnalysisState createState = newState != null ? newState : AnalysisState.NOT_SET;
            updated = qm.makeAnalysis(component, dtVuln, createState, newJustification, newResponse, newDetails, suppress);
        }

        if (newState != null && !Objects.equals(newState, oldState)) {
            qm.makeAnalysisComment(updated, "Analysis: %s → %s".formatted(oldState, newState), COMMENTER);
        }
        if (newJustification != null && !Objects.equals(newJustification, oldJustification)) {
            qm.makeAnalysisComment(updated, "Justification: %s → %s".formatted(oldJustification, newJustification), COMMENTER);
        }
        if (newDetails != null && !Objects.equals(newDetails, oldDetails)) {
            qm.makeAnalysisComment(updated, "Details: %s".formatted(newDetails), COMMENTER);
        }
        for (final AnalysisResponse response : responseTrail) {
            if (response != null && !Objects.equals(response, oldResponse)) {
                qm.makeAnalysisComment(updated, "Vendor Response: %s → %s".formatted(oldResponse, response), COMMENTER);
            }
        }
    }
}
