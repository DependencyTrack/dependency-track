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
package org.dependencytrack.vulnanalysis.trivy;

import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.ScoreMethod;
import org.cyclonedx.proto.v1_7.Severity;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityRating;
import trivy.proto.common.CVSS;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class TrivyModelConverter {

    private static final Pattern CWE_PATTERN = Pattern.compile("CWE-(\\d+)");

    private TrivyModelConverter() {
    }

    static Vulnerability.Builder convert(trivy.proto.common.Vulnerability trivyVuln) {
        final var vulnBuilder = Vulnerability.newBuilder();

        vulnBuilder.setId(trivyVuln.getVulnerabilityId());

        // Resolve source from vulnerability ID.
        final Source source = resolveSource(trivyVuln.getVulnerabilityId());
        vulnBuilder.setSource(source);

        // CVSS ratings from the severity source.
        final CVSS cvss = trivyVuln.getCvssMap().get(trivyVuln.getSeveritySource());
        if (cvss != null) {
            addRatings(vulnBuilder, cvss, trivyVuln.getSeveritySource());
        }

        // Severity
        vulnBuilder.addRatings(VulnerabilityRating.newBuilder()
                .setSeverity(mapSeverity(trivyVuln.getSeverity()))
                .build());

        // CWEs
        for (final String cweId : trivyVuln.getCweIdsList()) {
            final Matcher matcher = CWE_PATTERN.matcher(cweId);
            if (matcher.find()) {
                vulnBuilder.addCwes(Integer.parseInt(matcher.group(1)));
            }
        }

        // Description
        if (!trivyVuln.getDescription().isEmpty()) {
            vulnBuilder.setDescription(trivyVuln.getDescription());
        }

        // References as advisories
        for (final String ref : trivyVuln.getReferencesList()) {
            vulnBuilder.addAdvisories(
                    org.cyclonedx.proto.v1_7.Advisory.newBuilder()
                            .setUrl(ref)
                            .build());
        }

        // Title as property
        if (!trivyVuln.getTitle().isEmpty()) {
            vulnBuilder.addProperties(Property.newBuilder()
                    .setName("dependency-track:vuln:title")
                    .setValue(trivyVuln.getTitle())
                    .build());
        }

        // Timestamps: set created = published, matching legacy behavior.
        if (trivyVuln.hasPublishedDate()) {
            vulnBuilder.setCreated(trivyVuln.getPublishedDate());
            vulnBuilder.setPublished(trivyVuln.getPublishedDate());
        }
        if (trivyVuln.hasLastModifiedDate()) {
            vulnBuilder.setUpdated(trivyVuln.getLastModifiedDate());
        }

        // Fixed version as property
        if (!trivyVuln.getFixedVersion().isEmpty()) {
            vulnBuilder.addProperties(Property.newBuilder()
                    .setName("dependency-track:vuln:patched-versions")
                    .setValue(trivyVuln.getFixedVersion())
                    .build());
        }

        return vulnBuilder;
    }

    private static Source resolveSource(String vulnerabilityId) {
        if (vulnerabilityId.startsWith("CVE-")) {
            return Source.newBuilder().setName("NVD").build();
        }
        if (vulnerabilityId.startsWith("GHSA-")) {
            return Source.newBuilder().setName("GITHUB").build();
        }
        if (vulnerabilityId.startsWith("OSV-")) {
            return Source.newBuilder().setName("OSV").build();
        }
        if (vulnerabilityId.startsWith("SNYK-")) {
            return Source.newBuilder().setName("SNYK").build();
        }

        return Source.newBuilder().setName("UNKNOWN").build();
    }

    private static Severity mapSeverity(trivy.proto.common.Severity severity) {
        return switch (severity) {
            case CRITICAL -> Severity.SEVERITY_CRITICAL;
            case HIGH -> Severity.SEVERITY_HIGH;
            case MEDIUM -> Severity.SEVERITY_MEDIUM;
            case LOW -> Severity.SEVERITY_LOW;
            default -> Severity.SEVERITY_UNKNOWN;
        };
    }

    private static void addRatings(Vulnerability.Builder vulnBuilder, CVSS cvss, String severitySource) {
        final var ratingSource = Source.newBuilder().setName(severitySource).build();

        if (cvss.getV2Score() > 0.0 && !cvss.getV2Vector().isEmpty()) {
            vulnBuilder.addRatings(VulnerabilityRating.newBuilder()
                    .setSource(ratingSource)
                    .setScore(cvss.getV2Score())
                    .setMethod(ScoreMethod.SCORE_METHOD_CVSSV2)
                    .setVector(cvss.getV2Vector())
                    .build());
        }
        if (cvss.getV3Score() > 0.0 && !cvss.getV3Vector().isEmpty()) {
            final ScoreMethod method = cvss.getV3Vector().contains("CVSS:3.1")
                    ? ScoreMethod.SCORE_METHOD_CVSSV31
                    : ScoreMethod.SCORE_METHOD_CVSSV3;
            vulnBuilder.addRatings(VulnerabilityRating.newBuilder()
                    .setSource(ratingSource)
                    .setScore(cvss.getV3Score())
                    .setMethod(method)
                    .setVector(cvss.getV3Vector())
                    .build());
        }
        if (cvss.getV40Score() > 0.0 && !cvss.getV40Vector().isEmpty()) {
            vulnBuilder.addRatings(VulnerabilityRating.newBuilder()
                    .setSource(ratingSource)
                    .setScore(cvss.getV40Score())
                    .setMethod(ScoreMethod.SCORE_METHOD_CVSSV4)
                    .setVector(cvss.getV40Vector())
                    .build());
        }
    }

}
