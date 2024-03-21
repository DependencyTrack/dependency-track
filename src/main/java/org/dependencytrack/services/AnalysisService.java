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
package org.dependencytrack.services;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.exception.EntityNotFoundException;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.AnalysisRequest;
import org.dependencytrack.util.NotificationUtil;

import java.util.Optional;

/**
 * Service dedicated to managing Vulnerability Analysis, creating and updating them along with
 * the afferent comments management.
 */
public class AnalysisService implements AutoCloseable {

    private final QueryManager qm;

    public AnalysisService() {
        this.qm = new QueryManager();
    }

    /**
     * Retrieves an analysis from the database
     *
     * @param projectUuid
     * @param componentUuid
     * @param vulnerabilityUuid
     * @return the stored analysis
     * @throws EntityNotFoundException if project, component or vulnerability are not found
     */
    public Optional<Analysis> getAnalysis(String projectUuid, String componentUuid, String vulnerabilityUuid) throws EntityNotFoundException {
        if (StringUtils.trimToNull(projectUuid) != null) {
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            if (project == null) {
                throw new EntityNotFoundException("The project could not be found.");
            }
        }
        final Component component = qm.getObjectByUuid(Component.class, componentUuid);
        if (component == null) {
            throw new EntityNotFoundException("The component could not be found.");
        }
        final Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, vulnerabilityUuid);
        if (vulnerability == null) {
            throw new EntityNotFoundException("The vulnerability could not be found.");
        }

        Analysis analysis = qm.getAnalysis(component, vulnerability);
        if (analysis != null) {
            return Optional.of(analysis);
        }

        return Optional.empty();
    }

    /**
     * Creates or updates an analysis
     *
     * @param request
     * @param commenter
     * @return the created or updated analysis
     * @throws EntityNotFoundException if project, component or vulnerability are not found
     */
    public Analysis updateAnalysis(AnalysisRequest request, String commenter) throws EntityNotFoundException {
        final Project project = qm.getObjectByUuid(Project.class, request.getProject());
        if (project == null) {
            throw new EntityNotFoundException("The project could not be found.");
        }
        final Component component = qm.getObjectByUuid(Component.class, request.getComponent());
        if (component == null) {
            throw new EntityNotFoundException("The component could not be found.");
        }
        final Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, request.getVulnerability());
        if (vulnerability == null) {
            throw new EntityNotFoundException("The vulnerability could not be found.");
        }

        AnalysisDescriptionBuilder builder = new AnalysisDescriptionBuilder();
        builder.withState(request.getAnalysisState())
               .withJustification(request.getAnalysisJustification())
               .withDetails(request.getAnalysisDetails())
               .withResponse(request.getAnalysisResponse())
               .withSuppression(request.isSuppressed())
               .withComment(request.getComment());

        return this.updateAnalysis(builder.build(), component, vulnerability, commenter);
    }

    /**
     * Creates or updates an analysis
     *
     * @param analysisDescription
     * @param component
     * @param vulnerability
     * @param commenter
     * @return
     */
    public Analysis updateAnalysis(AnalysisDescription analysisDescription, Component component, Vulnerability vulnerability, String commenter) {

        Analysis analysis = qm.getAnalysis(component, vulnerability);

        boolean analysisStateChange = false;
        boolean suppressionChange = false;

        if (analysis != null) {
            analysisStateChange = makeStateComment(qm, analysis, analysisDescription.getAnalysisState(), commenter);
            makeJustificationComment(qm, analysis, analysisDescription.getAnalysisJustification(), commenter);
            AnalysisResponse response = null;
            for (AnalysisResponse vendorResponse: analysisDescription.getAnalysisResponses()) {
                makeAnalysisResponseComment(qm, analysis, vendorResponse, commenter);
                response = vendorResponse;
            }

            makeAnalysisDetailsComment(qm, analysis, analysisDescription.getAnalysisDetails(), commenter);
            suppressionChange = makeAnalysisSuppressionComment(qm, analysis, analysisDescription.isSuppressed(), commenter);

            analysis = qm.makeAnalysis(component, vulnerability,
                    analysisDescription.getAnalysisState(),
                    analysisDescription.getAnalysisJustification(),
                    response,
                    analysisDescription.getAnalysisDetails(),
                    analysisDescription.isSuppressed());
        } else {
            AnalysisResponse response = analysisDescription.getAnalysisResponses() != null
                    && !analysisDescription.getAnalysisResponses().isEmpty()
                    ? analysisDescription.getAnalysisResponses().get(analysisDescription.getAnalysisResponses().size()-1) : null;

            analysis = qm.makeAnalysis(component, vulnerability,
                    analysisDescription.getAnalysisState(),
                    analysisDescription.getAnalysisJustification(),
                    response,
                    analysisDescription.getAnalysisDetails(),
                    analysisDescription.isSuppressed());
            analysisStateChange = true; // this is a new analysis - so set to true because it was previously null
            makeFirstStateComment(qm, analysis, commenter);
            makeFirstJustificationComment(qm, analysis, commenter);
            for (int i=0; i<analysisDescription.getAnalysisResponses().size(); i++) {
                if (i == 0) {
                    makeFirstAnalysisResponseComment(qm, analysis, analysisDescription.getAnalysisResponses().get(i), commenter);
                } else {
                    makeAnalysisResponseComment(qm, analysis, analysisDescription.getAnalysisResponses().get(i), commenter);
                }
            }
            makeFirstDetailsComment(qm, analysis, commenter);
        }

        final String comment = StringUtils.trimToNull(analysisDescription.getComment());
        qm.makeAnalysisComment(analysis, comment, commenter);
        analysis = qm.getAnalysis(component, vulnerability);
        NotificationUtil.analyzeNotificationCriteria(qm, analysis, analysisStateChange, suppressionChange);

        return analysis;
    }

    private void makeFirstStateComment(final QueryManager qm, final Analysis analysis, final String commenter) {
        if (analysis.getAnalysisState() != null) {
            addAnalysisStateComment(qm, analysis, AnalysisState.NOT_SET, analysis.getAnalysisState(), commenter);
        }
    }

    private boolean makeStateComment(final QueryManager qm, final Analysis analysis, final AnalysisState analysisState, final String commenter) {
        boolean analysisStateChange = false;
        if (analysisState != null && analysisState != analysis.getAnalysisState()) {
            analysisStateChange = true;
            addAnalysisStateComment(qm, analysis, analysis.getAnalysisState(), analysisState, commenter);
        }
        return analysisStateChange;
    }

    private static void addAnalysisStateComment(QueryManager qm, Analysis analysis, AnalysisState before, AnalysisState after, String commenter) {
        qm.makeAnalysisComment(analysis, String.format("Analysis: %s → %s", before, after), commenter);
    }

    private void makeFirstJustificationComment(QueryManager qm, Analysis analysis, String commenter) {
        if (analysis.getAnalysisJustification() != null) {
            addAnalysisJustificationComment(qm, analysis, AnalysisJustification.NOT_SET, analysis.getAnalysisJustification(), commenter);
        }
    }

    private void makeJustificationComment(final QueryManager qm, final Analysis analysis, final AnalysisJustification analysisJustification, final String commenter) {
        if (analysisJustification != null) {
            if (analysis.getAnalysisJustification() == null && AnalysisJustification.NOT_SET != analysisJustification) {
                addAnalysisJustificationComment(qm, analysis, AnalysisJustification.NOT_SET, analysisJustification, commenter);
            } else if (analysis.getAnalysisJustification() != null && analysisJustification != analysis.getAnalysisJustification()) {
                addAnalysisJustificationComment(qm, analysis, analysis.getAnalysisJustification(), analysisJustification, commenter);
            }
        }
    }

    private static void addAnalysisJustificationComment(QueryManager qm, Analysis analysis, AnalysisJustification before, AnalysisJustification after, String commenter) {
        qm.makeAnalysisComment(analysis, String.format("Justification: %s → %s", before, after), commenter);
    }


    private void makeFirstAnalysisResponseComment(QueryManager qm, Analysis analysis, AnalysisResponse response, String commenter) {
        if (response != null && response != AnalysisResponse.NOT_SET) {
            addAnalysisResponseComment(qm, analysis, AnalysisResponse.NOT_SET, response, commenter);
        }
    }

    private void makeAnalysisResponseComment(final QueryManager qm, final Analysis analysis, final AnalysisResponse analysisResponse, final String commenter) {
        if (analysisResponse != null) {
            if (analysis.getAnalysisResponse() == null && analysis.getAnalysisResponse() != analysisResponse) {
                addAnalysisResponseComment(qm, analysis, AnalysisResponse.NOT_SET, analysisResponse, commenter);
            } else if (analysis.getAnalysisResponse() != null && analysis.getAnalysisResponse() != analysisResponse) {
                addAnalysisResponseComment(qm, analysis, analysis.getAnalysisResponse(), analysisResponse, commenter);
            }
        }
    }

    private static void addAnalysisResponseComment(QueryManager qm, Analysis analysis, AnalysisResponse before, AnalysisResponse after, String commenter) {
        qm.makeAnalysisComment(analysis, String.format("Vendor Response: %s → %s", before, after), commenter);
    }

    private void makeFirstDetailsComment(QueryManager qm, Analysis analysis, String commenter) {
        if (analysis.getAnalysisDetails() != null && !analysis.getAnalysisDetails().isEmpty()) {
            addAnalysisDetailsComment(qm, analysis, commenter);
        }
    }

    private void makeAnalysisDetailsComment(final QueryManager qm, final Analysis analysis, final String analysisDetails, final String commenter) {
        if (analysisDetails != null && !analysisDetails.equals(analysis.getAnalysisDetails())) {
            final String message = "Details: " + analysisDetails.trim();
            qm.makeAnalysisComment(analysis, message, commenter);
        }
    }

    private static void addAnalysisDetailsComment(QueryManager qm, Analysis analysis, String commenter) {
        final String message = "Details: " + analysis.getAnalysisDetails().trim();
        qm.makeAnalysisComment(analysis, message, commenter);
    }

    private boolean makeAnalysisSuppressionComment(final QueryManager qm, final Analysis analysis, final Boolean suppressed, final String commenter) {
        boolean suppressionChange = false;
        if (suppressed != null && analysis.isSuppressed() != suppressed) {
            suppressionChange = true;
            final String message = (suppressed) ? "Suppressed" : "Unsuppressed";
            qm.makeAnalysisComment(analysis, message, commenter);
        }
        return suppressionChange;
    }

    @Override
    public void close() {
        this.qm.close();
    }
}
