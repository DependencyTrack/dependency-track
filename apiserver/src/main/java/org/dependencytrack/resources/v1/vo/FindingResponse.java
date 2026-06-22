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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Scope;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability.Source;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/// OpenAPI representation of a finding returned by the v1 finding endpoints.
///
/// @since 5.1.0
@NullMarked
@Schema(name = "Finding", description = "A vulnerability finding for a project component")
public record FindingResponse(
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED) Component component,
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED) VulnerabilityDetails vulnerability,
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED) Analysis analysis,
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED) Attribution attribution,
        @Schema(description = "Composite project, component, and vulnerability identifier", requiredMode = Schema.RequiredMode.REQUIRED)
        String matrix) {

    @Schema(name = "FindingComponent")
    public record Component(
            @Schema(requiredMode = Schema.RequiredMode.REQUIRED) UUID uuid,
            @Nullable String name,
            @Nullable String group,
            @Nullable String version,
            @Nullable String purl,
            @Nullable String cpe,
            @Schema(description = "UUID of the project containing the component", requiredMode = Schema.RequiredMode.REQUIRED)
            UUID project,
            @Schema(requiredMode = Schema.RequiredMode.REQUIRED) boolean hasOccurrences,
            @Nullable Scope scope,
            @Nullable String projectName,
            @Nullable String projectVersion) {
    }

    @Schema(name = "FindingVulnerability")
    public record VulnerabilityDetails(
            @Schema(requiredMode = Schema.RequiredMode.REQUIRED) UUID uuid,
            @Nullable Source source,
            @Nullable String vulnId,
            @Nullable String title,
            @Nullable String subtitle,
            @Nullable String description,
            @Nullable String recommendation,
            @Nullable String references,
            @Nullable Severity severity,
            @Nullable Integer severityRank,
            @Nullable BigDecimal cvssV2BaseScore,
            @Nullable BigDecimal cvssV3BaseScore,
            @Nullable BigDecimal cvssV4Score,
            @Nullable String cvssV2Vector,
            @Nullable String cvssV3Vector,
            @Nullable String cvssV4Vector,
            @Nullable BigDecimal owaspLikelihoodScore,
            @Nullable BigDecimal owaspTechnicalImpactScore,
            @Nullable BigDecimal owaspBusinessImpactScore,
            @Nullable String owaspRRVector,
            @Nullable BigDecimal epssScore,
            @Nullable BigDecimal epssPercentile,
            @Nullable List<Cwe> cwes,
            @Schema(requiredMode = Schema.RequiredMode.REQUIRED) Set<Alias> aliases,
            @Schema(type = "integer", format = "int64", description = "Publication timestamp in milliseconds since the Unix epoch")
            @Nullable Long published) {
    }

    @Schema(name = "FindingCwe")
    public record Cwe(
            @Schema(requiredMode = Schema.RequiredMode.REQUIRED) int cweId,
            @Nullable String name) {
    }

    @Schema(name = "FindingVulnerabilityAlias")
    public record Alias(
            @Nullable String cveId,
            @Nullable String ghsaId,
            @Nullable String sonatypeId,
            @Nullable String osvId,
            @Nullable String snykId,
            @Nullable String vulnDbId) {
    }

    @Schema(name = "FindingAnalysis")
    public record Analysis(
            @Nullable AnalysisState state,
            @JsonProperty("isSuppressed")
            @Schema(requiredMode = Schema.RequiredMode.REQUIRED) boolean isSuppressed) {
    }

    @Schema(name = "FindingAttribution")
    public record Attribution(
            @Nullable String analyzerIdentity,
            @Schema(type = "integer", format = "int64", description = "Attribution timestamp in milliseconds since the Unix epoch")
            @Nullable Long attributedOn,
            @Nullable String alternateIdentifier,
            @Nullable String referenceUrl) {
    }
}
