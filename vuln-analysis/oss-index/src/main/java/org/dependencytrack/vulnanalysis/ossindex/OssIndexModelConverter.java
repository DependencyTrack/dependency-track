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
package org.dependencytrack.vulnanalysis.ossindex;

import org.cyclonedx.proto.v1_7.Advisory;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityRating;
import org.cyclonedx.proto.v1_7.VulnerabilityReference;
import org.jspecify.annotations.Nullable;
import org.metaeffekt.core.security.cvss.CvssVector;
import org.metaeffekt.core.security.cvss.v2.Cvss2;
import org.metaeffekt.core.security.cvss.v3.Cvss3P0;
import org.metaeffekt.core.security.cvss.v3.Cvss3P1;
import org.metaeffekt.core.security.cvss.v4P0.Cvss4P0;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV2;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV3;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV31;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV4;

/**
 * @since 5.0.0
 */
final class OssIndexModelConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(OssIndexModelConverter.class);
    private static final Pattern CWE_PATTERN = Pattern.compile("(cwe-)?(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final Source SOURCE_NVD = Source.newBuilder().setName("NVD").build();
    private static final Source SOURCE_OSSINDEX = Source.newBuilder().setName("OSSINDEX").build();

    private OssIndexModelConverter() {
    }

    static Vulnerability.Builder convert(
            ComponentReportVulnerability reportedVuln,
            boolean includeAliases) {
        final var vulnBuilder = Vulnerability.newBuilder()
                .setId(reportedVuln.id());

        if (reportedVuln.id().toLowerCase().startsWith("cve-")) {
            vulnBuilder.setSource(SOURCE_NVD);
        } else {
            vulnBuilder.setSource(SOURCE_OSSINDEX);
            if (includeAliases && reportedVuln.cve() != null) {
                vulnBuilder.addReferences(
                        VulnerabilityReference.newBuilder()
                                .setId(reportedVuln.cve())
                                .setSource(SOURCE_NVD)
                                .build());
            }
        }

        if (reportedVuln.title() != null) {
            vulnBuilder.addProperties(
                    Property.newBuilder()
                            .setName("dependency-track:vuln:title")
                            .setValue(reportedVuln.title())
                            .build());
        }

        if (reportedVuln.reference() != null) {
            vulnBuilder.addProperties(
                    Property.newBuilder()
                            .setName("dependency-track:vuln:reference-url")
                            .setValue(reportedVuln.reference())
                            .build());
        }

        if (reportedVuln.description() != null) {
            vulnBuilder.setDescription(reportedVuln.description());
        }

        if (reportedVuln.cwe() != null) {
            final Matcher matcher = CWE_PATTERN.matcher(reportedVuln.cwe());
            if (matcher.matches()) {
                vulnBuilder.addCwes(Integer.parseInt(matcher.group(2)));
            }
        }

        if (reportedVuln.reference() != null) {
            vulnBuilder.addAdvisories(
                    Advisory.newBuilder()
                            .setUrl(reportedVuln.reference())
                            .build());
        }
        if (reportedVuln.externalReferences() != null) {
            for (final String externalReference : reportedVuln.externalReferences()) {
                vulnBuilder.addAdvisories(
                        Advisory.newBuilder()
                                .setUrl(externalReference)
                                .build());
            }
        }

        final VulnerabilityRating rating = convertRating(reportedVuln.cvssVector());
        if (rating != null) {
            vulnBuilder.addRatings(rating);
        }

        return vulnBuilder;
    }

    private static @Nullable VulnerabilityRating convertRating(@Nullable String cvssVector) {
        if (cvssVector == null) {
            return null;
        }

        final CvssVector cvss = CvssVector.parseVector(cvssVector, true);
        if (cvss == null || !cvss.isBaseFullyDefined()) {
            LOGGER.warn("Failed to parse cvss vector '{}'; Ignoring", cvssVector);
            return null;
        }

        final double score = cvss.getBakedScores().getBaseScore();
        return switch (cvss) {
            case Cvss4P0 it -> VulnerabilityRating.newBuilder()
                    .setMethod(SCORE_METHOD_CVSSV4)
                    .setVector(it.toString())
                    .setScore(score)
                    .setSource(SOURCE_OSSINDEX)
                    .build();
            case Cvss3P1 it -> VulnerabilityRating.newBuilder()
                    .setMethod(SCORE_METHOD_CVSSV31)
                    .setVector(it.toString())
                    .setScore(score)
                    .setSource(SOURCE_OSSINDEX)
                    .build();
            case Cvss3P0 it -> VulnerabilityRating.newBuilder()
                    .setMethod(SCORE_METHOD_CVSSV3)
                    .setVector(it.toString())
                    .setScore(score)
                    .setSource(SOURCE_OSSINDEX)
                    .build();
            case Cvss2 it -> VulnerabilityRating.newBuilder()
                    .setMethod(SCORE_METHOD_CVSSV2)
                    .setVector("(" + it + ")")
                    .setScore(score)
                    .setSource(SOURCE_OSSINDEX)
                    .build();
            default -> null;
        };
    }

}
