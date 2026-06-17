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

import org.cyclonedx.proto.v1_7.Advisory;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityRating;
import org.cyclonedx.proto.v1_7.VulnerabilityReference;
import org.dependencytrack.vulnanalysis.vulndb.VulnDbApiResponse.CvssV2Metric;
import org.dependencytrack.vulnanalysis.vulndb.VulnDbApiResponse.CvssV3Metric;
import org.dependencytrack.vulnanalysis.vulndb.VulnDbApiResponse.NvdAdditionalInfo;
import org.jspecify.annotations.Nullable;
import org.metaeffekt.core.security.cvss.processor.BakedCvssVectorScores;
import org.metaeffekt.core.security.cvss.v2.Cvss2;
import org.metaeffekt.core.security.cvss.v3.Cvss3;
import org.metaeffekt.core.security.cvss.v3.Cvss3P0;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV2;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV3;

/**
 * @since 5.0.0
 */
final class VulnDbModelConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnDbModelConverter.class);
    private static final Pattern CWE_PATTERN = Pattern.compile("CWE-(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final Source SOURCE_NVD = Source.newBuilder().setName("NVD").build();
    private static final Source SOURCE_VULNDB = Source.newBuilder().setName("VULNDB").build();

    private VulnDbModelConverter() {
    }

    static Vulnerability.Builder convert(
            VulnDbApiResponse.Vulnerability vuln,
            boolean includeAliases) {
        final var vulnBuilder = Vulnerability.newBuilder()
                .setId(String.valueOf(vuln.vulndbId()))
                .setSource(SOURCE_VULNDB);

        final String description = buildDescription(vuln);
        if (description != null) {
            vulnBuilder.setDescription(description);
        }

        if (vuln.title() != null) {
            vulnBuilder.addProperties(
                    Property.newBuilder()
                            .setName("dependency-track:vuln:title")
                            .setValue(vuln.title())
                            .build());
        }

        if (vuln.authors() != null && !vuln.authors().isEmpty()) {
            final var credits = new StringBuilder();
            for (final var author : vuln.authors()) {
                if (author.name() != null) {
                    if (!credits.isEmpty()) {
                        credits.append(", ");
                    }
                    credits.append(author.name());
                }
            }
            if (!credits.isEmpty()) {
                vulnBuilder.addProperties(
                        Property.newBuilder()
                                .setName("dependency-track:vuln:credits")
                                .setValue(credits.toString())
                                .build());
            }
        }

        if (vuln.extReferences() != null) {
            for (final var extRef : vuln.extReferences()) {
                if (extRef.value() != null && !extRef.value().isBlank()) {
                    vulnBuilder.addAdvisories(
                            Advisory.newBuilder()
                                    .setUrl(extRef.value())
                                    .build());
                }
            }
        }

        // Prefer NVD-sourced metrics (those with a cve_id) over VulnDB's own.
        addCvssV2Rating(vulnBuilder, vuln.cvssV2Metrics());
        addCvssV3Rating(vulnBuilder, vuln.cvssV3Metrics());

        // Extract CVE aliases and CWEs from NVD additional info and CVSS metrics.
        final var cveIds = new HashSet<String>();
        extractCveIds(cveIds, vuln.cvssV2Metrics(), CvssV2Metric::cveId);
        extractCveIds(cveIds, vuln.cvssV3Metrics(), CvssV3Metric::cveId);
        extractCveIds(cveIds, vuln.nvdAdditionalInfo(), NvdAdditionalInfo::cveId);

        if (includeAliases) {
            for (final String cveId : cveIds) {
                vulnBuilder.addReferences(
                        VulnerabilityReference.newBuilder()
                                .setId(cveId)
                                .setSource(SOURCE_NVD)
                                .build());
            }
        }

        extractCwes(vulnBuilder, vuln.nvdAdditionalInfo());

        return vulnBuilder;
    }

    private static @Nullable String buildDescription(VulnDbApiResponse.Vulnerability vuln) {
        final var sb = new StringBuilder();
        appendIfPresent(sb, vuln.description());
        appendIfPresent(sb, vuln.technicalDescription());
        appendIfPresent(sb, vuln.solution());
        appendIfPresent(sb, vuln.manualNotes());
        return sb.isEmpty() ? null : sb.toString();
    }

    private static void appendIfPresent(StringBuilder sb, @Nullable String value) {
        if (value != null && !value.isBlank()) {
            if (!sb.isEmpty()) {
                sb.append("\n\n");
            }
            sb.append(value.strip());
        }
    }

    private static void addCvssV2Rating(
            Vulnerability.Builder vulnBuilder,
            @Nullable List<CvssV2Metric> metrics) {
        if (metrics == null || metrics.isEmpty()) {
            return;
        }

        // Prefer NVD-sourced metric (has cveId).
        CvssV2Metric preferred = null;
        for (final var metric : metrics) {
            if (metric.cveId() != null && !metric.cveId().isBlank()) {
                preferred = metric;
                break;
            }
        }
        if (preferred == null) {
            preferred = metrics.getFirst();
        }

        final Cvss2 cvss = buildCvssV2(preferred);
        if (cvss == null || !cvss.isBaseFullyDefined()) {
            return;
        }

        final BakedCvssVectorScores score = cvss.getBakedScores();
        vulnBuilder.addRatings(
                VulnerabilityRating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV2)
                        .setVector("(" + cvss + ")")
                        .setScore(score.getBaseScore())
                        .setSource(SOURCE_VULNDB)
                        .build());
    }

    private static void addCvssV3Rating(
            Vulnerability.Builder vulnBuilder,
            @Nullable List<CvssV3Metric> metrics) {
        if (metrics == null || metrics.isEmpty()) {
            return;
        }

        CvssV3Metric preferred = null;
        for (final var metric : metrics) {
            if (metric.cveId() != null && !metric.cveId().isBlank()) {
                preferred = metric;
                break;
            }
        }
        if (preferred == null) {
            preferred = metrics.getFirst();
        }

        final Cvss3P0 cvss = buildCvssV3(preferred);
        if (cvss == null || !cvss.isBaseFullyDefined()) {
            return;
        }

        final BakedCvssVectorScores score = cvss.getBakedScores();
        vulnBuilder.addRatings(
                VulnerabilityRating.newBuilder()
                        .setMethod(SCORE_METHOD_CVSSV3)
                        .setVector(cvss.toString())
                        .setScore(score.getBaseScore())
                        .setSource(SOURCE_VULNDB)
                        .build());
    }

    private static @Nullable Cvss2 buildCvssV2(CvssV2Metric metric) {
        try {
            final var cvss = new Cvss2();
            if (metric.accessVector() != null) {
                cvss.setAccessVector(mapCvssV2AccessVector(metric.accessVector()));
            }
            if (metric.accessComplexity() != null) {
                cvss.setAccessComplexity(mapCvssV2AccessComplexity(metric.accessComplexity()));
            }
            if (metric.authentication() != null) {
                cvss.setAuthentication(mapCvssV2Authentication(metric.authentication()));
            }
            if (metric.confidentialityImpact() != null) {
                cvss.setConfidentialityImpact(mapCvssV2Cia(metric.confidentialityImpact()));
            }
            if (metric.integrityImpact() != null) {
                cvss.setIntegrityImpact(mapCvssV2Cia(metric.integrityImpact()));
            }
            if (metric.availabilityImpact() != null) {
                cvss.setAvailabilityImpact(mapCvssV2Cia(metric.availabilityImpact()));
            }
            return cvss;
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Failed to construct CVSS v2 vector from metric fields", e);
            return null;
        }
    }

    private static @Nullable Cvss3P0 buildCvssV3(CvssV3Metric metric) {
        try {
            final var cvss = new Cvss3P0();
            if (metric.attackVector() != null) {
                cvss.setAttackVector(mapCvssV3AttackVector(metric.attackVector()));
            }
            if (metric.attackComplexity() != null) {
                cvss.setAttackComplexity(mapCvssV3AttackComplexity(metric.attackComplexity()));
            }
            if (metric.privilegesRequired() != null) {
                cvss.setPrivilegesRequired(mapCvssV3PrivilegesRequired(metric.privilegesRequired()));
            }
            if (metric.userInteraction() != null) {
                cvss.setUserInteraction(mapCvssV3UserInteraction(metric.userInteraction()));
            }
            if (metric.scope() != null) {
                cvss.setScope(mapCvssV3Scope(metric.scope()));
            }
            if (metric.confidentialityImpact() != null) {
                cvss.setConfidentialityImpact(mapCvssV3Cia(metric.confidentialityImpact()));
            }
            if (metric.integrityImpact() != null) {
                cvss.setIntegrityImpact(mapCvssV3Cia(metric.integrityImpact()));
            }
            if (metric.availabilityImpact() != null) {
                cvss.setAvailabilityImpact(mapCvssV3Cia(metric.availabilityImpact()));
            }
            return cvss;
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Failed to construct CVSS v3 vector from metric fields", e);
            return null;
        }
    }

    private static Cvss2.AccessVector mapCvssV2AccessVector(String value) {
        return switch (value.toUpperCase()) {
            case "NETWORK" -> Cvss2.AccessVector.NETWORK;
            case "ADJACENT", "ADJACENT_NETWORK" -> Cvss2.AccessVector.ADJACENT_NETWORK;
            case "LOCAL" -> Cvss2.AccessVector.LOCAL;
            default -> throw new IllegalArgumentException("Unknown CVSS v2 access vector: " + value);
        };
    }

    private static Cvss2.AccessComplexity mapCvssV2AccessComplexity(String value) {
        return switch (value.toUpperCase()) {
            case "LOW" -> Cvss2.AccessComplexity.LOW;
            case "MEDIUM" -> Cvss2.AccessComplexity.MEDIUM;
            case "HIGH" -> Cvss2.AccessComplexity.HIGH;
            default -> throw new IllegalArgumentException("Unknown CVSS v2 access complexity: " + value);
        };
    }

    private static Cvss2.Authentication mapCvssV2Authentication(String value) {
        return switch (value.toUpperCase()) {
            case "NONE" -> Cvss2.Authentication.NONE;
            case "SINGLE", "SINGLE_INSTANCE" -> Cvss2.Authentication.SINGLE;
            case "MULTIPLE", "MULTIPLE_INSTANCES" -> Cvss2.Authentication.MULTIPLE;
            default -> throw new IllegalArgumentException("Unknown CVSS v2 authentication: " + value);
        };
    }

    private static Cvss2.CIAImpact mapCvssV2Cia(String value) {
        return switch (value.toUpperCase()) {
            case "NONE" -> Cvss2.CIAImpact.NONE;
            case "PARTIAL" -> Cvss2.CIAImpact.PARTIAL;
            case "COMPLETE" -> Cvss2.CIAImpact.COMPLETE;
            default -> throw new IllegalArgumentException("Unknown CVSS v2 CIA: " + value);
        };
    }

    private static Cvss3.AttackVector mapCvssV3AttackVector(String value) {
        return switch (value.toUpperCase()) {
            case "NETWORK" -> Cvss3.AttackVector.NETWORK;
            case "ADJACENT", "ADJACENT_NETWORK" -> Cvss3.AttackVector.ADJACENT_NETWORK;
            case "LOCAL" -> Cvss3.AttackVector.LOCAL;
            case "PHYSICAL" -> Cvss3.AttackVector.PHYSICAL;
            default -> throw new IllegalArgumentException("Unknown CVSS v3 attack vector: " + value);
        };
    }

    private static Cvss3.AttackComplexity mapCvssV3AttackComplexity(String value) {
        return switch (value.toUpperCase()) {
            case "LOW" -> Cvss3.AttackComplexity.LOW;
            case "HIGH" -> Cvss3.AttackComplexity.HIGH;
            default -> throw new IllegalArgumentException("Unknown CVSS v3 attack complexity: " + value);
        };
    }

    private static Cvss3.PrivilegesRequired mapCvssV3PrivilegesRequired(String value) {
        return switch (value.toUpperCase()) {
            case "NONE" -> Cvss3.PrivilegesRequired.NONE;
            case "LOW" -> Cvss3.PrivilegesRequired.LOW;
            case "HIGH" -> Cvss3.PrivilegesRequired.HIGH;
            default -> throw new IllegalArgumentException("Unknown CVSS v3 privileges required: " + value);
        };
    }

    private static Cvss3.UserInteraction mapCvssV3UserInteraction(String value) {
        return switch (value.toUpperCase()) {
            case "NONE" -> Cvss3.UserInteraction.NONE;
            case "REQUIRED" -> Cvss3.UserInteraction.REQUIRED;
            default -> throw new IllegalArgumentException("Unknown CVSS v3 user interaction: " + value);
        };
    }

    private static Cvss3.Scope mapCvssV3Scope(String value) {
        return switch (value.toUpperCase()) {
            case "UNCHANGED" -> Cvss3.Scope.UNCHANGED;
            case "CHANGED" -> Cvss3.Scope.CHANGED;
            default -> throw new IllegalArgumentException("Unknown CVSS v3 scope: " + value);
        };
    }

    private static Cvss3.CIAImpact mapCvssV3Cia(String value) {
        return switch (value.toUpperCase()) {
            case "NONE" -> Cvss3.CIAImpact.NONE;
            case "LOW" -> Cvss3.CIAImpact.LOW;
            case "HIGH" -> Cvss3.CIAImpact.HIGH;
            default -> throw new IllegalArgumentException("Unknown CVSS v3 CIA: " + value);
        };
    }

    private static <T> void extractCveIds(
            HashSet<String> cveIds,
            @Nullable List<T> items,
            Function<T, @Nullable String> cveIdExtractor) {
        if (items == null) {
            return;
        }

        for (final var item : items) {
            final String cveId = cveIdExtractor.apply(item);
            if (cveId != null && !cveId.isBlank()) {
                cveIds.add(cveId);
            }
        }
    }

    private static void extractCwes(Vulnerability.Builder vulnBuilder, @Nullable List<NvdAdditionalInfo> nvdInfos) {
        if (nvdInfos == null) {
            return;
        }

        for (final var info : nvdInfos) {
            if (info.cweId() == null) {
                continue;
            }
            final Matcher matcher = CWE_PATTERN.matcher(info.cweId());
            if (matcher.find()) {
                vulnBuilder.addCwes(Integer.parseInt(matcher.group(1)));
            }
        }
    }

}
