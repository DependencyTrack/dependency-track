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
package org.dependencytrack.resources.v1.vo;

import alpine.common.validation.RegexSequence;
import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/**
 * Defines a custom request object used when updating analysis decisions.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public class AnalysisRequest {

    private static final String RISK_IMPACT_PATTERN = "LOW|MEDIUM|HIGH|CRITICAL";
    private static final String RISK_LIKELIHOOD_PATTERN = "VIRTUALLY_IMPOSSIBLE|UNLIKELY|POSSIBLE|LIKELY|ALMOST_CERTAIN";

    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The project must be a valid 36 character UUID")
    private final String project;

    @NotNull
    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The component must be a valid 36 character UUID")
    private final String component;

    @NotNull
    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The vulnerability must be a valid 36 character UUID")
    private final String vulnerability;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The comment may only contain printable characters")
    private final String comment;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The comment may only contain printable characters")
    private final String analysisDetails;

    private final AnalysisState analysisState;

    private final AnalysisJustification analysisJustification;

    private final AnalysisResponse analysisResponse;

    @Pattern(regexp = RISK_IMPACT_PATTERN, message = "The risk impact must be a valid option")
    private final String riskImpact;

    @Pattern(regexp = RISK_LIKELIHOOD_PATTERN, message = "The risk likelihood must be a valid option")
    private final String riskLikelihood;

    @Pattern(regexp = RISK_IMPACT_PATTERN, message = "The residual risk impact must be a valid option")
    private final String residualRiskImpact;

    @Pattern(regexp = RISK_LIKELIHOOD_PATTERN, message = "The residual risk likelihood must be a valid option")
    private final String residualRiskLikelihood;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The risk justification may only contain printable characters")
    private final String riskJustification;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The residual risk justification may only contain printable characters")
    private final String residualRiskJustification;

    private final Boolean suppressed; // Optional. If not specified, we do not want to set value to false, thus using Boolean object rather than primitive.

    @JsonCreator
    public AnalysisRequest(@JsonProperty(value = "project") String project,
                           @JsonProperty(value = "component", required = true) String component,
                           @JsonProperty(value = "vulnerability", required = true) String vulnerability,
                           @JsonProperty(value = "analysisState") AnalysisState analysisState,
                           @JsonProperty(value = "analysisJustification") AnalysisJustification analysisJustification,
                           @JsonProperty(value = "analysisResponse") AnalysisResponse analysisResponse,
                           @JsonProperty(value = "analysisDetails") String analysisDetails,
                           @JsonProperty(value = "comment") String comment,
                           @JsonProperty(value = "riskImpact") String riskImpact,
                           @JsonProperty(value = "riskLikelihood") String riskLikelihood,
                           @JsonProperty(value = "residualRiskImpact") String residualRiskImpact,
                           @JsonProperty(value = "residualRiskLikelihood") String residualRiskLikelihood,
                           @JsonProperty(value = "riskJustification") String riskJustification,
                           @JsonProperty(value = "residualRiskJustification") String residualRiskJustification,
                           @JsonProperty(value = "isSuppressed") Boolean suppressed) {
        this.project = project;
        this.component = component;
        this.vulnerability = vulnerability;
        this.analysisState = analysisState;
        this.analysisJustification = analysisJustification;
        this.analysisResponse = analysisResponse;
        this.analysisDetails = analysisDetails;
        this.comment = comment;
        this.riskImpact = riskImpact;
        this.riskLikelihood = riskLikelihood;
        this.residualRiskImpact = residualRiskImpact;
        this.residualRiskLikelihood = residualRiskLikelihood;
        this.riskJustification = riskJustification;
        this.residualRiskJustification = residualRiskJustification;
        this.suppressed = suppressed;
    }

    public AnalysisRequest(String project,
                           String component,
                           String vulnerability,
                           AnalysisState analysisState,
                           AnalysisJustification analysisJustification,
                           AnalysisResponse analysisResponse,
                           String analysisDetails,
                           String comment,
                           Boolean suppressed) {
        this(project, component, vulnerability, analysisState, analysisJustification, analysisResponse,
                analysisDetails, comment, null, null, null, null, null, null, suppressed);
    }

    public String getProject() {
        return project;
    }

    public String getComponent() {
        return component;
    }

    public String getVulnerability() {
        return vulnerability;
    }

    public AnalysisState getAnalysisState() {
        if (analysisState == null) {
            return AnalysisState.NOT_SET;
        } else {
            return analysisState;
        }
    }

    public AnalysisJustification getAnalysisJustification() {
        if (analysisJustification == null) {
            return AnalysisJustification.NOT_SET;
        } else {
            return analysisJustification;
        }
    }

    public AnalysisResponse getAnalysisResponse() {
        if (analysisResponse == null) {
            return AnalysisResponse.NOT_SET;
        } else {
            return analysisResponse;
        }
    }

    public String getAnalysisDetails() {
        return analysisDetails;
    }

    public String getComment() {
        return comment;
    }

    public Boolean isSuppressed() {
        return suppressed;
    }

    public String getRiskImpact() {
        return StringUtils.trimToNull(riskImpact);
    }

    public String getRiskLikelihood() {
        return StringUtils.trimToNull(riskLikelihood);
    }

    public String getResidualRiskImpact() {
        return StringUtils.trimToNull(residualRiskImpact);
    }

    public String getResidualRiskLikelihood() {
        return StringUtils.trimToNull(residualRiskLikelihood);
    }

    public String getRiskJustification() {
        return StringUtils.trimToNull(riskJustification);
    }

    public String getResidualRiskJustification() {
        return StringUtils.trimToNull(residualRiskJustification);
    }
}
