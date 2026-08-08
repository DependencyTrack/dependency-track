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
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Scope;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability.Source;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/// OpenAPI representation of a finding returned by the v1 finding endpoints.
///
/// @since 5.1.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "Finding", description = "A vulnerability finding for a project component")
public record FindingResponse(
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED) Component component,
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED) VulnerabilityDetails vulnerability,
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED) Analysis analysis,
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED) Attribution attribution,
        @Schema(description = "Composite project, component, and vulnerability identifier", requiredMode = Schema.RequiredMode.REQUIRED)
        String matrix) {

    public static FindingResponse of(final Finding finding) {
        final Map<String, Object> component = finding.getComponent();
        final Map<String, Object> vulnerability = finding.getVulnerability();
        final Map<String, Object> analysis = finding.getAnalysis();
        final Map<String, Object> attribution = finding.getAttribution();

        return new FindingResponse(
                new Component(
                        value(component, "uuid", UUID.class),
                        value(component, "name", String.class),
                        value(component, "group", String.class),
                        value(component, "version", String.class),
                        value(component, "purl", String.class),
                        value(component, "cpe", String.class),
                        value(component, "project", UUID.class),
                        Boolean.TRUE.equals(component.get("hasOccurrences")),
                        enumValue(component, "scope", Scope.class),
                        value(component, "projectName", String.class),
                        value(component, "projectVersion", String.class),
                        value(component, "latestVersion", String.class)),
                new VulnerabilityDetails(
                        value(vulnerability, "uuid", UUID.class),
                        enumValue(vulnerability, "source", Source.class),
                        value(vulnerability, "vulnId", String.class),
                        value(vulnerability, "title", String.class),
                        value(vulnerability, "subtitle", String.class),
                        value(vulnerability, "description", String.class),
                        value(vulnerability, "recommendation", String.class),
                        value(vulnerability, "references", String.class),
                        enumValue(vulnerability, "severity", Severity.class),
                        value(vulnerability, "severityRank", Integer.class),
                        value(vulnerability, "cvssV2BaseScore", BigDecimal.class),
                        value(vulnerability, "cvssV3BaseScore", BigDecimal.class),
                        value(vulnerability, "cvssV4Score", BigDecimal.class),
                        value(vulnerability, "cvssV2Vector", String.class),
                        value(vulnerability, "cvssV3Vector", String.class),
                        value(vulnerability, "cvssV4Vector", String.class),
                        value(vulnerability, "owaspLikelihoodScore", BigDecimal.class),
                        value(vulnerability, "owaspTechnicalImpactScore", BigDecimal.class),
                        value(vulnerability, "owaspBusinessImpactScore", BigDecimal.class),
                        value(vulnerability, "owaspRRVector", String.class),
                        value(vulnerability, "epssScore", BigDecimal.class),
                        value(vulnerability, "epssPercentile", BigDecimal.class),
                        cwes(vulnerability.get("cwes")),
                        aliases(vulnerability.get("aliases")),
                        timestamp(vulnerability.get("published"))),
                new Analysis(
                        enumValue(analysis, "state", AnalysisState.class),
                        Boolean.TRUE.equals(analysis.get("isSuppressed"))),
                new Attribution(
                        value(attribution, "analyzerIdentity", String.class),
                        timestamp(attribution.get("attributedOn")),
                        value(attribution, "alternateIdentifier", String.class),
                        value(attribution, "referenceUrl", String.class)),
                finding.getMatrix());
    }

    private static <T> @Nullable T value(final Map<String, Object> values, final String key, final Class<T> type) {
        return type.cast(values.get(key));
    }

    private static <E extends Enum<E>> @Nullable E enumValue(
            final Map<String, Object> values,
            final String key,
            final Class<E> type) {
        final Object value = values.get(key);
        if (value == null) {
            return null;
        }
        return value instanceof String stringValue ? Enum.valueOf(type, stringValue) : type.cast(value);
    }

    private static @Nullable Long timestamp(final @Nullable Object value) {
        return value instanceof Date date ? date.getTime() : null;
    }

    private static @Nullable List<Cwe> cwes(final @Nullable Object value) {
        if (!(value instanceof List<?> cwes)) {
            return null;
        }
        return cwes.stream()
                .map(org.dependencytrack.model.Cwe.class::cast)
                .map(cwe -> new Cwe(cwe.getCweId(), cwe.getName()))
                .toList();
    }

    private static Set<Alias> aliases(final @Nullable Object value) {
        if (!(value instanceof Set<?> aliases)) {
            return Set.of();
        }
        return aliases.stream()
                .map(Map.class::cast)
                .map(alias -> new Alias(
                        (String) alias.get("cveId"),
                        (String) alias.get("ghsaId"),
                        (String) alias.get("sonatypeId"),
                        (String) alias.get("osvId"),
                        (String) alias.get("snykId"),
                        (String) alias.get("vulnDbId")))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    @Schema(name = "FindingComponent")
    @JsonInclude(JsonInclude.Include.NON_NULL)
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
            @Nullable String projectVersion,
            @Nullable String latestVersion) {
    }

    @Schema(name = "FindingVulnerability")
    @JsonInclude(JsonInclude.Include.NON_NULL)
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
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Cwe(
            @Schema(requiredMode = Schema.RequiredMode.REQUIRED) int cweId,
            @Nullable String name) {
    }

    @Schema(name = "FindingVulnerabilityAlias")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Alias(
            @Nullable String cveId,
            @Nullable String ghsaId,
            @Nullable String sonatypeId,
            @Nullable String osvId,
            @Nullable String snykId,
            @Nullable String vulnDbId) {
    }

    @Schema(name = "FindingAnalysis")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Analysis(
            @Nullable AnalysisState state,
            @JsonProperty("isSuppressed")
            @Schema(requiredMode = Schema.RequiredMode.REQUIRED) boolean isSuppressed) {
    }

    @Schema(name = "FindingAttribution")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Attribution(
            @Nullable String analyzerIdentity,
            @Schema(type = "integer", format = "int64", description = "Attribution timestamp in milliseconds since the Unix epoch")
            @Nullable Long attributedOn,
            @Nullable String alternateIdentifier,
            @Nullable String referenceUrl) {
    }
}
