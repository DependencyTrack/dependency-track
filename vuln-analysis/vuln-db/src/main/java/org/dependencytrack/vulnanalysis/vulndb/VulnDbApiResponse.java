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
package org.dependencytrack.vulnanalysis.vulndb;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * @since 5.0.0
 */
final class VulnDbApiResponse {

    private VulnDbApiResponse() {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record PaginatedResponse(
            @JsonProperty("current_page") int currentPage,
            @JsonProperty("total_entries") int totalEntries,
            List<Vulnerability> results) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Vulnerability(
            @JsonProperty("vulndb_id") int vulndbId,
            @Nullable String title,
            @JsonProperty("disclosure_date") @Nullable String disclosureDate,
            @Nullable String description,
            @Nullable String solution,
            @JsonProperty("vulndb_last_modified") @Nullable String lastModified,
            @JsonProperty("manual_notes") @Nullable String manualNotes,
            @JsonProperty("t_description") @Nullable String technicalDescription,
            @Nullable List<Author> authors,
            @JsonProperty("ext_references") @Nullable List<ExternalReference> extReferences,
            @JsonProperty("cvss_metrics") @Nullable List<CvssV2Metric> cvssV2Metrics,
            @JsonProperty("cvss_version_three_metrics") @Nullable List<CvssV3Metric> cvssV3Metrics,
            @JsonProperty("nvd_additional_information") @Nullable List<NvdAdditionalInfo> nvdAdditionalInfo) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Author(
            @Nullable String name,
            @Nullable String company) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record ExternalReference(
            @Nullable String type,
            @Nullable String value) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record CvssV2Metric(
            @JsonProperty("access_vector") @Nullable String accessVector,
            @JsonProperty("access_complexity") @Nullable String accessComplexity,
            @Nullable String authentication,
            @JsonProperty("confidentiality_impact") @Nullable String confidentialityImpact,
            @JsonProperty("integrity_impact") @Nullable String integrityImpact,
            @JsonProperty("availability_impact") @Nullable String availabilityImpact,
            @JsonProperty("calculated_cvss_base_score") double calculatedCvssBaseScore,
            @JsonProperty("cve_id") @Nullable String cveId,
            @Nullable String source) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record CvssV3Metric(
            @JsonProperty("attack_vector") @Nullable String attackVector,
            @JsonProperty("attack_complexity") @Nullable String attackComplexity,
            @JsonProperty("privileges_required") @Nullable String privilegesRequired,
            @JsonProperty("user_interaction") @Nullable String userInteraction,
            @Nullable String scope,
            @JsonProperty("confidentiality_impact") @Nullable String confidentialityImpact,
            @JsonProperty("integrity_impact") @Nullable String integrityImpact,
            @JsonProperty("availability_impact") @Nullable String availabilityImpact,
            @JsonProperty("calculated_cvss_base_score") double calculatedCvssBaseScore,
            @JsonProperty("cve_id") @Nullable String cveId,
            @Nullable String source) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record NvdAdditionalInfo(
            @Nullable String summary,
            @JsonProperty("cwe_id") @Nullable String cweId,
            @JsonProperty("cve_id") @Nullable String cveId) {
    }

}
