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
package org.dependencytrack.resources.v1;

import alpine.common.validation.RegexSequence;
import alpine.common.validation.ValidationTask;
import alpine.model.ApiKey;
import alpine.model.Team;
import alpine.model.UserPrincipal;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.AnalysisRequest;
import alpine.model.ConfigProperty;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.util.AnalysisCommentUtil;
import org.dependencytrack.util.JsonUtil;
import org.dependencytrack.util.NotificationUtil;
import org.json.JSONArray;
import org.json.JSONObject;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * JAX-RS resources for processing analysis decisions.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@Path("/v1/analysis")
@Tag(name = "analysis")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class AnalysisResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Retrieves an analysis trail",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "An analysis trail",
                    content = @Content(schema = @Schema(implementation = Analysis.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The project, component, or vulnerability could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response retrieveAnalysis(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"))
                                     @QueryParam("project") String projectUuid,
                                     @Parameter(description = "The UUID of the component", schema = @Schema(type = "string", format = "uuid"), required = true)
                                     @QueryParam("component") String componentUuid,
                                     @Parameter(description = "The UUID of the vulnerability", schema = @Schema(type = "string", format = "uuid"), required = true)
                                     @QueryParam("vulnerability") String vulnerabilityUuid) {
        failOnValidationError(
                new ValidationTask(RegexSequence.Pattern.UUID, projectUuid, "Project is not a valid UUID", false), // this is optional
                new ValidationTask(RegexSequence.Pattern.UUID, componentUuid, "Component is not a valid UUID"),
                new ValidationTask(RegexSequence.Pattern.UUID, vulnerabilityUuid, "Vulnerability is not a valid UUID")
        );
        try (QueryManager qm = new QueryManager()) {
            final Project project;
            if (StringUtils.trimToNull(projectUuid) != null) {
                project = qm.getObjectByUuid(Project.class, projectUuid);
                if (project == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
                }
            }
            final Component component = qm.getObjectByUuid(Component.class, componentUuid);
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            final Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, vulnerabilityUuid);
            if (vulnerability == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The vulnerability could not be found.").build();
            }
            final Analysis analysis = qm.getAnalysis(component, vulnerability);
            if (analysis == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("No analysis exists.").build();
            }
            return Response.ok(analysis).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Records an analysis decision",
            description = "<p>Requires permission <strong>VULNERABILITY_ANALYSIS</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The created analysis",
                    content = @Content(schema = @Schema(implementation = Analysis.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The project, component, or vulnerability could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS)
    public Response updateAnalysis(AnalysisRequest request) {
        final Validator validator = getValidator();
        failOnValidationError(
                validator.validateProperty(request, "project"),
                validator.validateProperty(request, "component"),
                validator.validateProperty(request, "vulnerability"),
                validator.validateProperty(request, "analysisState"),
                validator.validateProperty(request, "analysisJustification"),
                validator.validateProperty(request, "analysisResponse"),
                validator.validateProperty(request, "analysisDetails"),
                validator.validateProperty(request, "comment"),
                validator.validateProperty(request, "riskImpact"),
                validator.validateProperty(request, "riskLikelihood"),
                validator.validateProperty(request, "residualRiskImpact"),
                validator.validateProperty(request, "residualRiskLikelihood"),
                validator.validateProperty(request, "riskJustification"),
                validator.validateProperty(request, "residualRiskJustification")
        );
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, request.getProject());
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            final Component component = qm.getObjectByUuid(Component.class, request.getComponent());
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            final Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, request.getVulnerability());
            if (vulnerability == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The vulnerability could not be found.").build();
            }

            String commenter = null;
            if (getPrincipal() instanceof UserPrincipal principal) {
                commenter = principal.getUsername();
            } else if (getPrincipal() instanceof ApiKey apiKey) {
                List<Team> teams = apiKey.getTeams();
                List<String> teamNames = new ArrayList<>();
                teams.forEach(team -> teamNames.add(team.getName()));
                commenter = String.join(", ", teamNames);
            }

            Analysis analysis = qm.getAnalysis(component, vulnerability);
            if (analysis == null) {
                analysis = qm.makeAnalysis(component, vulnerability, AnalysisState.NOT_SET, AnalysisJustification.NOT_SET, AnalysisResponse.NOT_SET, null, false);
            }
            final var analysisStateChange = AnalysisCommentUtil.makeStateComment(qm, analysis, request.getAnalysisState(), commenter);
            AnalysisCommentUtil.makeJustificationComment(qm, analysis, request.getAnalysisJustification(), commenter);
            AnalysisCommentUtil.makeAnalysisResponseComment(qm, analysis, request.getAnalysisResponse(), commenter);
            AnalysisCommentUtil.makeAnalysisDetailsComment(qm, analysis, request.getAnalysisDetails(), commenter);
            // Resolve custom label names from risk matrix config (section + axis labels, fall back to defaults)
            String impactLabel = "Risk impact";
            String likelihoodLabel = "Risk likelihood";
            String residualImpactLabel = "Residual risk impact";
            String residualLikelihoodLabel = "Residual risk likelihood";
            String effectiveRiskSection = "Risk";
            String effectiveResidualSection = "Residual risk";
            String levelDefinitionsLabel = "calculated";
            JSONObject matrixConfig = null;
            final ConfigProperty riskMatrixProp = qm.getConfigProperty(
                    ConfigPropertyConstants.RISK_MATRIX_CONFIG.getGroupName(),
                    ConfigPropertyConstants.RISK_MATRIX_CONFIG.getPropertyName());
            if (riskMatrixProp != null && !JsonUtil.isBlankJson(riskMatrixProp.getPropertyValue())) {
                try {
                    matrixConfig = new JSONObject(riskMatrixProp.getPropertyValue());
                    if (matrixConfig.optBoolean("enabled", false)) {
                        final JSONObject sectionLabels = matrixConfig.optJSONObject("sectionLabels");
                        final JSONObject axisLabels = matrixConfig.optJSONObject("axisLabels");
                        final String riskSection = sectionLabels != null ? sectionLabels.optString("riskAssessment", "").trim() : "";
                        final String residualSection = sectionLabels != null ? sectionLabels.optString("residualRisk", "").trim() : "";
                        final String impactAxis = axisLabels != null ? axisLabels.optString("impact", "impact").trim() : "impact";
                        final String likelihoodAxis = axisLabels != null ? axisLabels.optString("likelihood", "likelihood").trim() : "likelihood";
                        final String customLevelLabel = matrixConfig.optString("levelDefinitionsLabel", "").trim();
                        effectiveRiskSection = riskSection.isEmpty() ? "Risk" : riskSection;
                        effectiveResidualSection = residualSection.isEmpty() ? "Residual risk" : residualSection;
                        levelDefinitionsLabel = customLevelLabel.isEmpty() ? "calculated" : customLevelLabel;
                        impactLabel = effectiveRiskSection + " " + impactAxis;
                        likelihoodLabel = effectiveRiskSection + " " + likelihoodAxis;
                        residualImpactLabel = effectiveResidualSection + " " + impactAxis;
                        residualLikelihoodLabel = effectiveResidualSection + " " + likelihoodAxis;
                    }
                } catch (Exception ignored) { }
            }
            AnalysisCommentUtil.makeRiskImpactComment(qm, analysis, request.getRiskImpact(), commenter, impactLabel);
            AnalysisCommentUtil.makeRiskLikelihoodComment(qm, analysis, request.getRiskLikelihood(), commenter, likelihoodLabel);
            AnalysisCommentUtil.makeResidualRiskImpactComment(qm, analysis, request.getResidualRiskImpact(), commenter, residualImpactLabel);
            AnalysisCommentUtil.makeResidualRiskLikelihoodComment(qm, analysis, request.getResidualRiskLikelihood(), commenter, residualLikelihoodLabel);
            AnalysisCommentUtil.makeRiskJustificationComment(qm, analysis, request.getRiskJustification(), commenter, effectiveRiskSection + " justification");
            AnalysisCommentUtil.makeResidualRiskJustificationComment(qm, analysis, request.getResidualRiskJustification(), commenter, effectiveResidualSection + " justification");
            // Log derived calculated risk level (changes when impact or likelihood changes)
            AnalysisCommentUtil.makeCalculatedRiskComment(qm, analysis,
                    resolveCalculatedLevel(matrixConfig, analysis.getRiskImpact(), analysis.getRiskLikelihood()),
                    resolveCalculatedLevel(matrixConfig, request.getRiskImpact(), request.getRiskLikelihood()),
                    effectiveRiskSection + " " + levelDefinitionsLabel, commenter);
            AnalysisCommentUtil.makeCalculatedRiskComment(qm, analysis,
                    resolveCalculatedLevel(matrixConfig, analysis.getResidualRiskImpact(), analysis.getResidualRiskLikelihood()),
                    resolveCalculatedLevel(matrixConfig, request.getResidualRiskImpact(), request.getResidualRiskLikelihood()),
                    effectiveResidualSection + " " + levelDefinitionsLabel, commenter);
            final var suppressionChange = AnalysisCommentUtil.makeAnalysisSuppressionComment(qm, analysis, request.isSuppressed(), commenter);
            // Compute calculated risk level keys to store in DB
            final String newRiskCalculated = resolveCalculatedLevel(matrixConfig, request.getRiskImpact(), request.getRiskLikelihood());
            final String newResidualRiskCalculated = resolveCalculatedLevel(matrixConfig, request.getResidualRiskImpact(), request.getResidualRiskLikelihood());
            analysis = qm.makeAnalysis(component, vulnerability, request.getAnalysisState(), request.getAnalysisJustification(),
                    request.getAnalysisResponse(), request.getAnalysisDetails(), request.isSuppressed(),
                    request.getRiskImpact(), request.getRiskLikelihood(),
                    request.getResidualRiskImpact(), request.getResidualRiskLikelihood(),
                    request.getRiskJustification(), request.getResidualRiskJustification(),
                    newRiskCalculated, newResidualRiskCalculated);

            final String comment = StringUtils.trimToNull(request.getComment());
            qm.makeAnalysisComment(analysis, comment, commenter);
            analysis = qm.getAnalysis(component, vulnerability);
            NotificationUtil.analyzeNotificationCriteria(qm, analysis, analysisStateChange, suppressionChange);
            return Response.ok(analysis).build();
        }
    }

    /**
     * Resolves the display label of the calculated risk level for a given impact + likelihood combination
     * by looking up the cell in the risk matrix config, then finding the matching level's label.
     *
     * @param matrixConfig the parsed risk matrix JSON config (may be null)
     * @param impactKey    the impact key (e.g., "HIGH")
     * @param likelihoodKey the likelihood key (e.g., "POSSIBLE")
     * @return the level label (e.g., "High Risk"), or null if not resolvable
     */
    private static String resolveCalculatedLevel(final JSONObject matrixConfig, final String impactKey, final String likelihoodKey) {
        if (matrixConfig == null || impactKey == null || likelihoodKey == null) return null;
        if (!matrixConfig.optBoolean("enabled", false)) return null;
        final JSONObject cells = matrixConfig.optJSONObject("cells");
        if (cells == null) return null;
        // Cell key format: "LIKELIHOOD_KEY::IMPACT_KEY" (matches frontend lookupRiskEntry logic)
        final JSONObject cell = cells.optJSONObject(likelihoodKey + "::" + impactKey);
        if (cell == null) return null;
        final String levelKey = cell.optString("levelKey", null);
        if (levelKey == null) return null;
        final JSONArray levels = matrixConfig.optJSONArray("levels");
        if (levels == null) return null;
        for (int i = 0; i < levels.length(); i++) {
            final JSONObject level = levels.optJSONObject(i);
            if (level != null && levelKey.equals(level.optString("key", null))) {
                return level.optString("label", levelKey);
            }
        }
        return null;
    }

}
