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
package org.dependencytrack.vulnanalysis.snyk;

import com.google.protobuf.util.Timestamps;
import org.cyclonedx.proto.v1_7.Advisory;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.ScoreMethod;
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

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV2;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV3;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV31;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV4;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_OTHER;

/**
 * @since 5.0.0
 */
final class SnykModelConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(SnykModelConverter.class);
    private static final Pattern VULN_ID_PATTERN = Pattern.compile("^SNYK-.+$");
    private static final Pattern CWE_PATTERN = Pattern.compile("(CWE-)?(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final Source SOURCE_SNYK = Source.newBuilder().setName("SNYK").build();
    private static final Source SOURCE_NVD = Source.newBuilder().setName("NVD").build();
    private static final Source SOURCE_GITHUB = Source.newBuilder().setName("GITHUB").build();
    private static final List<String> SEVERITY_SOURCE_PRIORITY = List.of("NVD", "Snyk", "Red Hat", "SUSE");

    private SnykModelConverter() {
    }

    static Vulnerability.Builder convert(SnykIssue issue, boolean includeAliases) {
        final var vulnBuilder = Vulnerability.newBuilder();

        final String vulnId = resolveVulnId(issue);
        vulnBuilder.setId(vulnId);
        vulnBuilder.setSource(SOURCE_SNYK);

        final SnykIssue.Attributes attrs = issue.attributes();

        if (attrs.title() != null) {
            vulnBuilder.addProperties(
                    Property.newBuilder()
                            .setName("dependency-track:vuln:title")
                            .setValue(attrs.title())
                            .build());
        }

        vulnBuilder.addProperties(
                Property.newBuilder()
                        .setName("dependency-track:vuln:reference-url")
                        .setValue("https://security.snyk.io/vuln/" + vulnId)
                        .build());

        if (attrs.description() != null) {
            vulnBuilder.setDescription(attrs.description());
        }

        convertTimestamp(attrs.createdAt()).ifPresent(vulnBuilder::setCreated);
        convertTimestamp(attrs.updatedAt()).ifPresent(vulnBuilder::setUpdated);

        if (attrs.problems() != null) {
            for (final SnykIssue.Problem problem : attrs.problems()) {
                if (includeAliases) {
                    final VulnerabilityReference ref = convertToReference(problem);
                    if (ref != null) {
                        vulnBuilder.addReferences(ref);
                    }
                }

                final Integer cweId = convertToCwe(problem);
                if (cweId != null) {
                    vulnBuilder.addCwes(cweId);
                }
            }
        }

        if (attrs.severities() != null) {
            attrs.severities().stream()
                    .sorted(compareSeverities())
                    .map(SnykModelConverter::convertSeverity)
                    .filter(Objects::nonNull)
                    .<ArrayList<VulnerabilityRating>>collect(
                            ArrayList::new,
                            (ratings, rating) -> {
                                if (ratings.stream().noneMatch(r -> r.getMethod() == rating.getMethod())) {
                                    ratings.add(rating);
                                }
                            },
                            ArrayList::addAll)
                    .forEach(vulnBuilder::addRatings);
        }

        if (attrs.slots() != null) {
            if (attrs.slots().references() != null) {
                for (final SnykIssue.Reference ref : attrs.slots().references()) {
                    vulnBuilder.addAdvisories(Advisory.newBuilder().setUrl(ref.url()));
                }
            }

            convertTimestamp(attrs.slots().publicationTime()).ifPresent(vulnBuilder::setPublished);
        }

        if (attrs.coordinates() != null) {
            final var recommendations = new ArrayList<String>();
            for (final SnykIssue.Coordinate coordinate : attrs.coordinates()) {
                if (coordinate.remedies() != null) {
                    for (final SnykIssue.Remedy remedy : coordinate.remedies()) {
                        if (remedy.description() != null) {
                            recommendations.add(remedy.description());
                        }
                    }
                }
            }
            if (!recommendations.isEmpty()) {
                vulnBuilder.setRecommendation(String.join(System.lineSeparator(), recommendations));
            }
        }

        return vulnBuilder;
    }

    static @Nullable String getIssuePurl(SnykIssue issue) {
        final SnykIssue.Attributes attrs = issue.attributes();
        if (attrs.coordinates() == null || attrs.coordinates().isEmpty()) {
            return null;
        }

        final SnykIssue.Coordinate coordinate = attrs.coordinates().getFirst();
        if (coordinate.representations() == null || coordinate.representations().size() < 2) {
            return null;
        }

        final SnykIssue.Representation representation = coordinate.representations().get(1);
        if (representation.pkg() == null) {
            return null;
        }

        final String url = representation.pkg().url();
        if (url == null || url.isBlank()) {
            return null;
        }

        return url;
    }

    private static String resolveVulnId(SnykIssue issue) {
        final String issueId = issue.id();
        if (VULN_ID_PATTERN.matcher(issueId).matches()) {
            return issueId;
        }

        // Legacy ID: look for SNYK source in problems array.
        if (issue.attributes().problems() != null) {
            for (final SnykIssue.Problem problem : issue.attributes().problems()) {
                if ("SNYK".equals(problem.source())
                        && problem.id() != null
                        && VULN_ID_PATTERN.matcher(problem.id()).matches()) {
                    return problem.id();
                }
            }
        }

        LOGGER.warn("""
                Vulnerability {} does not match the expected ID pattern, and does not specify \
                an alternative ID in the "problems" array""", issueId);
        return issueId;
    }

    private static @Nullable VulnerabilityReference convertToReference(SnykIssue.Problem problem) {
        return switch (problem.source()) {
            case "CVE" -> VulnerabilityReference.newBuilder()
                    .setId(problem.id())
                    .setSource(SOURCE_NVD)
                    .build();
            case "GHSA" -> VulnerabilityReference.newBuilder()
                    .setId(problem.id())
                    .setSource(SOURCE_GITHUB)
                    .build();
            default -> null;
        };
    }

    private static @Nullable Integer convertToCwe(SnykIssue.Problem problem) {
        if (!"CWE".equals(problem.source())) {
            return null;
        }
        final Matcher matcher = CWE_PATTERN.matcher(problem.id());
        if (matcher.matches()) {
            return Integer.parseInt(matcher.group(2));
        }
        return null;
    }

    private static @Nullable VulnerabilityRating convertSeverity(SnykIssue.Severity severity) {
        if (severity.vector() == null) {
            return null;
        }

        final ScoreMethod scoreMethod = determineScoreMethod(severity.vector());
        final var ratingBuilder = VulnerabilityRating.newBuilder()
                .setMethod(scoreMethod)
                .setVector(severity.vector());

        if (severity.score() != null) {
            ratingBuilder.setScore(severity.score());
        }

        final Source source = mapSeveritySource(severity.source());
        if (source != null) {
            ratingBuilder.setSource(source);
        }

        return ratingBuilder.build();
    }

    private static ScoreMethod determineScoreMethod(String vector) {
        final CvssVector cvss = CvssVector.parseVector(vector, true);
        if (cvss == null) {
            LOGGER.warn("Failed to determine score method: CVSS vector {} is malformed", vector);
            return SCORE_METHOD_OTHER;
        }
        return switch (cvss) {
            case Cvss4P0 _ -> SCORE_METHOD_CVSSV4;
            case Cvss3P1 _ -> SCORE_METHOD_CVSSV31;
            case Cvss3P0 _ -> SCORE_METHOD_CVSSV3;
            case Cvss2 _ -> SCORE_METHOD_CVSSV2;
            default -> SCORE_METHOD_OTHER;
        };
    }

    private static @Nullable Source mapSeveritySource(String source) {
        return switch (source) {
            case "NVD" -> SOURCE_NVD;
            case "Snyk" -> SOURCE_SNYK;
            default -> null;
        };
    }

    private static Comparator<SnykIssue.Severity> compareSeverities() {
        return (left, right) -> {
            final int priorityLeft = SEVERITY_SOURCE_PRIORITY.indexOf(left.source());
            final int priorityRight = SEVERITY_SOURCE_PRIORITY.indexOf(right.source());
            final int effectiveLeft = priorityLeft >= 0 ? priorityLeft : 99;
            final int effectiveRight = priorityRight >= 0 ? priorityRight : 99;

            final int priorityResult = Integer.compare(effectiveLeft, effectiveRight);
            if (priorityResult != 0) {
                return priorityResult;
            }

            if (left.score() != null && right.score() == null) {
                return -1;
            } else if (left.score() == null && right.score() != null) {
                return 1;
            }

            if (left.score() != null && right.score() != null) {
                final int scoreResult = Float.compare(right.score(), left.score());
                if (scoreResult != 0) {
                    return scoreResult;
                }
            }

            if (left.vector() != null && right.vector() == null) {
                return -1;
            } else if (left.vector() == null && right.vector() != null) {
                return 1;
            }

            return left.source().compareTo(right.source());
        };
    }

    private static Optional<com.google.protobuf.Timestamp> convertTimestamp(@Nullable String isoTimestamp) {
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
