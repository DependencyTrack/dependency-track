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

import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.cyclonedx.proto.v1_7.Advisory;
import org.cyclonedx.proto.v1_7.Severity;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityRating;
import org.cyclonedx.proto.v1_7.VulnerabilityReference;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV2;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV3;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV4;
import static org.cyclonedx.proto.v1_7.Severity.SEVERITY_CRITICAL;
import static org.cyclonedx.proto.v1_7.Severity.SEVERITY_HIGH;
import static org.cyclonedx.proto.v1_7.Severity.SEVERITY_LOW;
import static org.cyclonedx.proto.v1_7.Severity.SEVERITY_MEDIUM;
import static org.cyclonedx.proto.v1_7.Severity.SEVERITY_UNKNOWN;

/**
 * Converts Checkmarx vulnerability data to CycloneDX vulnerability format.
 */
final class CheckmarxModelConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(CheckmarxModelConverter.class);
    private static final Pattern CWE_PATTERN = Pattern.compile("(CWE-)?(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final Source SOURCE_CX = Source.newBuilder().setName("CX").build();
    private static final Source SOURCE_NVD = Source.newBuilder().setName("NVD").build();

    private CheckmarxModelConverter() {
    }

    static Vulnerability.Builder convert(CheckmarxDataObject.Vulnerability cxVuln, CheckmarxDataObject.Remediation remediation, boolean aliasSyncEnabled) {
        final var vulnBuilder = Vulnerability.newBuilder();

        vulnBuilder.setId(cxVuln.cxId());
        vulnBuilder.setSource(SOURCE_CX);

        var vulnDetails = cxVuln.details();

        if (vulnDetails.description() != null) {
            vulnBuilder.setDescription(vulnDetails.description());
        }

        convertTimestamp(vulnDetails.created()).ifPresent(vulnBuilder::setCreated);
        convertTimestamp(vulnDetails.updatedTime()).ifPresent(vulnBuilder::setUpdated);
        convertTimestamp(vulnDetails.published()).ifPresent(vulnBuilder::setPublished);

        if (aliasSyncEnabled && cxVuln.cve() != null) {
            vulnBuilder.addReferences(VulnerabilityReference.newBuilder()
                    .setId(cxVuln.cve())
                    .setSource(SOURCE_NVD).build());
        }

        final Integer cweId = convertToCwe(vulnDetails.cwe());
        if (cweId != null) {
            vulnBuilder.addCwes(cweId);
        }

        if (vulnDetails.references() != null) {
            for (final var ref : vulnDetails.references()) {
                vulnBuilder.addAdvisories(Advisory.newBuilder().setUrl(ref.url()));
            }
        }

        if (remediation != null) {
            final var recommendations = new ArrayList<String>();
            if (remediation.nearest() != null) {
                recommendations.add("Smallest package upgrade that resolves the identified risks in the current package version: " + remediation.nearest().version());
            }
            if (remediation.latest() != null) {
                recommendations.add("Latest version of the package: " + remediation.latest().version());
            }
            if (!recommendations.isEmpty()) {
                vulnBuilder.setRecommendation(String.join(System.lineSeparator(), recommendations));
            }
        }

        if (vulnDetails.cvss4() != null) {
            final var cvss4 = vulnDetails.cvss4();
            final var ratingBuilder = VulnerabilityRating.newBuilder()
                    .setMethod(SCORE_METHOD_CVSSV4)
                    .setVector(cvss4.vector())
                    .setScore(cvss4.baseScore())
                    .setSeverity(convertSeverity(cvss4.severity()));
            vulnBuilder.addRatings(ratingBuilder.build());
        }

        if (vulnDetails.cvss3() != null) {
            final var cvss3 = vulnDetails.cvss3();
            final var ratingBuilder = VulnerabilityRating.newBuilder()
                    .setMethod(SCORE_METHOD_CVSSV3)
                    .setVector(cvss3.vector())
                    .setScore(cvss3.baseScore())
                    .setSeverity(convertSeverity(cvss3.severity()));
            vulnBuilder.addRatings(ratingBuilder.build());
        }

        if (vulnDetails.cvss2() != null) {
            final var cvss2 = vulnDetails.cvss2();
            final var ratingBuilder = VulnerabilityRating.newBuilder()
                    .setMethod(SCORE_METHOD_CVSSV2)
                    .setVector(cvss2.vector())
                    .setScore(cvss2.baseScore())
                    .setSeverity(convertSeverity(cvss2.severity()));
            vulnBuilder.addRatings(ratingBuilder.build());
        }

        return vulnBuilder;
    }

    private static Severity convertSeverity(String severity) {
        return switch (severity) {
            case "Critical" -> SEVERITY_CRITICAL;
            case "High" -> SEVERITY_HIGH;
            case "Medium" -> SEVERITY_MEDIUM;
            case "Low" -> SEVERITY_LOW;
            default -> SEVERITY_UNKNOWN;
        };
    }

    private static @Nullable Integer convertToCwe(String cwe) {
        final Matcher matcher = CWE_PATTERN.matcher(cwe);
        if (matcher.matches()) {
            return Integer.parseInt(matcher.group(2));
        }
        return null;
    }

    private static Optional<Timestamp> convertTimestamp(@Nullable String isoTimestamp) {
        if (isoTimestamp == null || isoTimestamp.isBlank()) {
            return Optional.empty();
        }

        try {
            final Instant instant = Instant.parse(isoTimestamp);
            return Optional.of(Timestamps.fromMillis(instant.toEpochMilli()));
        } catch (DateTimeParseException e) {
            LOGGER.warn("Failed to parse timestamp '{}'; Ignoring", isoTimestamp, e);
            return Optional.empty();
        }
    }
}
