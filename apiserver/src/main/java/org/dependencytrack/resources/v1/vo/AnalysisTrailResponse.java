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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.util.Date;
import java.util.List;

/// @since 5.2.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AnalysisTrailResponse(
        @Schema(description = "The state of the analysis decision", requiredMode = Schema.RequiredMode.REQUIRED)
        AnalysisState analysisState,

        @Schema(description = "The justification of the analysis decision") @Nullable
        AnalysisJustification analysisJustification,

        @Schema(description = "The vendor response to the vulnerability") @Nullable
        AnalysisResponse analysisResponse,

        @Schema(description = "Free-form details of the analysis decision") @Nullable
        String analysisDetails,

        @Schema(description = "Audit trail of analysis comments", requiredMode = Schema.RequiredMode.REQUIRED)
        List<Comment> analysisComments,

        @JsonProperty("isSuppressed")
        @Schema(description = "Whether the finding is suppressed", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean isSuppressed,

        @Schema(description = "Severity assigned by the analysis") @Nullable
        Severity severity,

        @Schema(description = "CVSS v2 vector assigned by the analysis") @Nullable
        String cvssV2Vector,

        @Schema(description = "CVSS v2 score assigned by the analysis") @Nullable
        BigDecimal cvssV2Score,

        @Schema(description = "CVSS v3 vector assigned by the analysis") @Nullable
        String cvssV3Vector,

        @Schema(description = "CVSS v3 score assigned by the analysis") @Nullable
        BigDecimal cvssV3Score,

        @Schema(description = "CVSS v4 vector assigned by the analysis") @Nullable
        String cvssV4Vector,

        @Schema(description = "CVSS v4 score assigned by the analysis") @Nullable
        BigDecimal cvssV4Score,

        @Schema(description = "OWASP Risk Rating vector assigned by the analysis") @Nullable
        String owaspVector,

        @Schema(description = "OWASP Risk Rating score assigned by the analysis") @Nullable
        BigDecimal owaspScore) {

    public static AnalysisTrailResponse of(Analysis analysis) {
        final List<AnalysisComment> jdoComments = analysis.getAnalysisComments();
        final List<Comment> comments =
                jdoComments != null ? jdoComments.stream().map(Comment::of).toList() : List.of();

        return new AnalysisTrailResponse(
                analysis.getAnalysisState(),
                analysis.getAnalysisJustification(),
                analysis.getAnalysisResponse(),
                analysis.getAnalysisDetails(),
                comments,
                analysis.isSuppressed(),
                analysis.getSeverity(),
                analysis.getCvssV2Vector(),
                analysis.getCvssV2Score(),
                analysis.getCvssV3Vector(),
                analysis.getCvssV3Score(),
                analysis.getCvssV4Vector(),
                analysis.getCvssV4Score(),
                analysis.getOwaspVector(),
                analysis.getOwaspScore());
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Comment(
            @Schema(description = "Timestamp the comment was recorded at", requiredMode = Schema.RequiredMode.REQUIRED)
            Date timestamp,

            @Schema(description = "The comment text", requiredMode = Schema.RequiredMode.REQUIRED)
            String comment,

            @Schema(description = "Identifier of the user who wrote the comment") @Nullable
            String commenter) {

        public static Comment of(AnalysisComment jdo) {
            return new Comment(jdo.getTimestamp(), jdo.getComment(), jdo.getCommenter());
        }
    }
}
