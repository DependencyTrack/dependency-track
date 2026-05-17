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

import org.apache.commons.collections4.CollectionUtils;
import org.cyclonedx.model.Bom;
import org.cyclonedx.util.BomLink;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertCdxVulnAnalysisJustificationToDtAnalysisJustification;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertCdxVulnAnalysisStateToDtAnalysisState;

public class CycloneDXVexImporter {

    private static final Logger LOGGER = LoggerFactory.getLogger(CycloneDXVexImporter.class);

    private static final String COMMENTER = "CycloneDX VEX";

    public void applyVex(final QueryManager qm, final Bom bom, final Project project) {
        if (bom.getVulnerabilities() == null || bom.getVulnerabilities().isEmpty()) {
            LOGGER.info("The uploaded VEX does not contain any vulnerabilities; Skipping VEX import");
            return;
        }
        if (!qm.hasVulnerabilities(project)) {
            LOGGER.info("The project {} does not have any vulnerabilities; Skipping VEX import", project);
            return;
        }

        final List<org.cyclonedx.model.vulnerability.Vulnerability> vexVulns = getApplicableVexVulnerabilities(bom.getVulnerabilities());
        if (vexVulns.isEmpty()) {
            LOGGER.info("The uploaded VEX does not contain any applicable vulnerabilities; Skipping VEX import");
            return;
        }

        final Map<String, BomRefTarget> targetByBomRef = indexComponents(bom);
        final Map<String, List<Component>> componentsByBomRef = new HashMap<>();

        for (final org.cyclonedx.model.vulnerability.Vulnerability vexVuln : vexVulns) {
            final Vulnerability dtVuln = qm.getVulnerabilityByVulnId(vexVuln.getSource().getName(), vexVuln.getId());
            if (dtVuln == null) {
                LOGGER.warn("""
                        VEX contains analysis for vulnerability {}/{}, but the project is not affected by it. \
                        Analyses can currently only be applied to existing findings.\
                        """, vexVuln.getSource().getName(), vexVuln.getId());
                continue;
            }

            List<Component> vulnerableComponents = null;

            for (final org.cyclonedx.model.vulnerability.Vulnerability.Affect affect : vexVuln.getAffects()) {
                final String affectedBomRef = affect.getRef();
                final BomRefTarget target = affectedBomRef != null
                        ? targetByBomRef.get(affectedBomRef)
                        : null;

                final boolean isProjectScoped =
                        (target != null && target.isMetadataComponent())
                                || (target == null && affectedBomRef != null && BomLink.isBomLink(affectedBomRef));

                if (isProjectScoped) {
                    if (vulnerableComponents == null) {
                        vulnerableComponents = qm.getAllVulnerableComponents(project, dtVuln);
                    }
                    for (final Component component : vulnerableComponents) {
                        updateAnalysis(qm, component, dtVuln, vexVuln);
                    }
                } else if (target != null) {
                    final List<Component> components = componentsByBomRef.computeIfAbsent(affectedBomRef, ignored -> {
                        final var cid = new ComponentIdentity(target.component());
                        return qm.matchIdentity(project, cid);
                    });
                    for (final Component component : components) {
                        updateAnalysis(qm, component, dtVuln, vexVuln);
                    }
                } else {
                    LOGGER.warn("""
                            Unable to locate affected element (metadata.component or components[].component) \
                            based on the BOM reference {}. The vulnerability.affects[].ref \
                            node of {}/{} is not resolvable; Skipping it\
                            """, affectedBomRef, vexVuln.getSource().getName(), vexVuln.getId());
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
                LOGGER.warn(
                        "VEX vulnerability at position #{} does not have an ID and / or source; Skipping it",
                        vexVulnPos);
                continue;
            }

            final String vexVulnId = vexVuln.getId();
            final String vexVulnSource = vexVuln.getSource().getName();
            if (!Vulnerability.Source.isKnownSource(vexVulnSource)) {
                LOGGER.warn(
                        "VEX vulnerability {}/{} at position #{} is from an unsupported source; Skipping it",
                        vexVulnSource, vexVulnId, vexVulnPos);
                continue;
            }
            if (CollectionUtils.isEmpty(vexVuln.getAffects())) {
                LOGGER.debug(
                        "VEX vulnerability {}/{} at position #{} does not have an affects node; Skipping it",
                        vexVulnSource, vexVulnId, vexVulnPos);
                continue;
            }
            if (vexVuln.getAnalysis() == null) {
                LOGGER.debug(
                        "VEX vulnerability {}/{} at position #{} does not have an analysis; Skipping it",
                        vexVulnSource, vexVulnId, vexVulnPos);
                continue;
            }

            applicableVulns.add(vexVuln);
        }

        return applicableVulns;
    }

    private record BomRefTarget(org.cyclonedx.model.Component component, boolean isMetadataComponent) {
    }

    private static Map<String, BomRefTarget> indexComponents(final Bom bom) {
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
            final List<org.cyclonedx.model.Component> components,
            final Map<String, BomRefTarget> targetByBomRef,
            final boolean metadataComponent) {
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

    private static void updateAnalysis(final QueryManager qm, final Component component, final Vulnerability vuln,
                                       final org.cyclonedx.model.vulnerability.Vulnerability cdxVuln) {
        final AnalysisState state =
                convertCdxVulnAnalysisStateToDtAnalysisState(cdxVuln.getAnalysis().getState());
        final AnalysisJustification justification =
                convertCdxVulnAnalysisJustificationToDtAnalysisJustification(cdxVuln.getAnalysis().getJustification());

        // CycloneDX supports multiple responses, DT only one.
        // The decision to effectively pick the last one is legacy behavior,
        // there's no other particular reason for doing it.
        final AnalysisResponse response;
        if (cdxVuln.getAnalysis().getResponses() != null
                && !cdxVuln.getAnalysis().getResponses().isEmpty()) {
            response = cdxVuln.getAnalysis().getResponses().stream()
                    .map(ModelConverter::convertCdxVulnAnalysisResponseToDtAnalysisResponse)
                    .toList()
                    .getLast();
        } else {
            response = null;
        }

        final boolean isSuppressed =
                state == AnalysisState.FALSE_POSITIVE
                        || state == AnalysisState.NOT_AFFECTED
                        || state == AnalysisState.RESOLVED;

        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vuln)
                        .withState(state)
                        .withJustification(justification)
                        .withResponse(response)
                        .withDetails(cdxVuln.getAnalysis().getDetail())
                        .withCommenter(COMMENTER)
                        .withSuppress(isSuppressed));
    }

}
