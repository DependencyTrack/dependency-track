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
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisComment;
import org.dependencytrack.model.ViolationAnalysisState;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.Date;
import java.util.List;

/// @since 5.1.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ViolationAnalysisResponse(
        @Schema(description = "The state of the analysis decision", requiredMode = Schema.RequiredMode.REQUIRED)
        ViolationAnalysisState analysisState,

        @Schema(description = "Audit trail of analysis comments", requiredMode = Schema.RequiredMode.REQUIRED)
        List<Comment> analysisComments,

        @JsonProperty("isSuppressed")
        @Schema(description = "Whether the policy violation is suppressed", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean isSuppressed) {

    public static ViolationAnalysisResponse of(ViolationAnalysis analysis) {
        final List<ViolationAnalysisComment> jdoComments = analysis.getAnalysisComments();
        final List<Comment> comments = jdoComments != null
                ? jdoComments.stream().map(Comment::of).toList()
                : List.of();

        return new ViolationAnalysisResponse(
                analysis.getAnalysisState(),
                comments,
                analysis.isSuppressed());
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Comment(
            @Schema(description = "Timestamp the comment was recorded at", requiredMode = Schema.RequiredMode.REQUIRED)
            Date timestamp,

            @Schema(description = "The comment text", requiredMode = Schema.RequiredMode.REQUIRED)
            String comment,

            @Schema(description = "Identifier of the user who wrote the comment")
            @Nullable String commenter) {

        public static Comment of(ViolationAnalysisComment jdo) {
            return new Comment(jdo.getTimestamp(), jdo.getComment(), jdo.getCommenter());
        }

    }
}
