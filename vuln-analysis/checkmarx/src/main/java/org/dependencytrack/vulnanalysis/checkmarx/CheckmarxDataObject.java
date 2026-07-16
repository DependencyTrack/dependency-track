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
package org.dependencytrack.vulnanalysis.checkmarx;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * Represents package and vulnerability data from Checkmarx API response.
 */
public record CheckmarxDataObject(Package pkg, List<Vulnerability> vulnerabilities) {

    record Package(String purl, String name, String version, @Nullable Remediation remediation) {}

    record Vulnerability(String cve, String cxId, Double score, String severity, VulnerabilityDetail details) {}

    record VulnerabilityDetail(
            @Nullable String description,
            @Nullable String cwe,
            @JsonProperty("created") String created,
            @JsonProperty("published") String published,
            @JsonProperty("updatedTime") String updatedTime,
            @Nullable List<Reference> references,
            @Nullable Cvss cvss2,
            @Nullable Cvss cvss3,
            @Nullable Cvss cvss4
    ) {}

    record Reference(String url) {}

    record Cvss(Double baseScore, String severity, @Nullable String vector) {}

    record Remediation(RemedyVersion latest, RemedyVersion nearest) {}

    record RemedyVersion(String version) {}
}

