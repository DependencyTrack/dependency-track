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
package org.dependencytrack.vulndatasource.jvn;

import com.google.protobuf.util.Timestamps;
import io.github.nscuro.versatile.Comparator;
import io.github.nscuro.versatile.Vers;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Classification;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.ExternalReference;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.ScoreMethod;
import org.cyclonedx.proto.v1_7.Severity;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityAffectedVersions;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.cyclonedx.proto.v1_7.VulnerabilityRating;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

/**
 * Converts a parsed {@link JvnAdvisory} into a CycloneDX Bill of Vulnerabilities (BOV).
 * <p>
 * Reuses the {@code Component} + {@code VulnerabilityAffects} emission shape of the NVD data source.
 * The JVN-specific parts are: CPE 2.2 to 2.3 normalisation, and translation of the free-text
 * Japanese {@code VersionNumber} into {@code vers} ranges via {@link JvnVersionParser}.
 *
 * @since 5.1.0
 */
final class ModelConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ModelConverter.class);
    private static final Source SOURCE_JVN = Source.newBuilder().setName("JVN").build();
    private static final String TITLE_PROPERTY = "dependency-track:vuln:title";
    private static final String VERS_SCHEME = "generic";

    private ModelConverter() {
    }

    static Bom convert(final JvnAdvisory advisory) {
        // Store every JVN advisory as-is under the JVN source, keyed by its JVNDB id. No CVE->NVD
        // routing and no NVD duplicate check: a JVN record and the NVD's CVE record may coexist.
        final Vulnerability.Builder vulnBuilder = Vulnerability.newBuilder()
                .setSource(SOURCE_JVN)
                .setId(advisory.jvnDbId())
                .addAllRatings(parseRatings(advisory.cvssList()));

        if (advisory.overview() != null && !advisory.overview().isBlank()) {
            vulnBuilder.setDescription(advisory.overview());
        }
        if (advisory.detail() != null && !advisory.detail().isBlank()) {
            vulnBuilder.setDetail(advisory.detail());
        }
        if (advisory.recommendation() != null && !advisory.recommendation().isBlank()) {
            vulnBuilder.setRecommendation(advisory.recommendation());
        }
        if (advisory.title() != null && !advisory.title().isBlank()) {
            vulnBuilder.addProperties(Property.newBuilder()
                    .setName(TITLE_PROPERTY)
                    .setValue(advisory.title()));
        }
        if (!advisory.cweIds().isEmpty()) {
            vulnBuilder.addAllCwes(advisory.cweIds());
        }
        if (advisory.datePublic() != null) {
            vulnBuilder.setPublished(Timestamps.fromMillis(advisory.datePublic().toEpochMilli()));
        }
        if (advisory.dateLastUpdated() != null) {
            vulnBuilder.setUpdated(Timestamps.fromMillis(advisory.dateLastUpdated().toEpochMilli()));
        }

        final var componentByCpe = new HashMap<String, Component>();
        final var affectsBuilderByBomRef = new HashMap<String, VulnerabilityAffects.Builder>();

        for (final JvnAdvisory.AffectedProduct product : advisory.affected()) {
            final Cpe cpe;
            final String cpe23;
            try {
                cpe = CpeParser.parse(product.cpe22());
                cpe23 = cpe.toCpe23FS();
            } catch (CpeParsingException e) {
                LOGGER.debug("Skipping unparseable CPE '{}' of {}", product.cpe22(), advisory.jvnDbId());
                continue;
            }

            // Skip non-concrete products (e.g. cpe:/a:misc:multiple_vendors would never map to a
            // concrete component anyway; "*"/"-" would match everything from a vendor).
            final String productName = cpe.getProduct();
            if ("*".equals(productName) || "-".equals(productName)) {
                continue;
            }

            final Component component = componentByCpe.computeIfAbsent(cpe23, ref -> Component.newBuilder()
                    .setBomRef(UUID.nameUUIDFromBytes(ref.getBytes()).toString())
                    .setType(determineComponentType(cpe))
                    .setPublisher(cpe.getVendor())
                    .setName(cpe.getProduct())
                    .setCpe(ref)
                    .build());

            final VulnerabilityAffects.Builder affectsBuilder = affectsBuilderByBomRef.computeIfAbsent(
                    component.getBomRef(),
                    bomRef -> VulnerabilityAffects.newBuilder().setRef(bomRef));

            addAffectedVersions(advisory, product, affectsBuilder);
        }

        final List<Component> components = componentByCpe.values().stream()
                .sorted(java.util.Comparator.comparing(Component::getBomRef))
                .toList();
        final List<VulnerabilityAffects> affects = affectsBuilderByBomRef.values().stream()
                .map(VulnerabilityAffects.Builder::build)
                .sorted(java.util.Comparator.comparing(VulnerabilityAffects::getRef))
                .toList();

        final Bom.Builder bomBuilder = Bom.newBuilder()
                .addAllComponents(components)
                .addVulnerabilities(vulnBuilder.addAllAffects(affects).build());
        for (final String url : advisory.referenceUrls()) {
            bomBuilder.addExternalReferences(ExternalReference.newBuilder().setUrl(url).build());
        }
        return bomBuilder.build();
    }

    private static void addAffectedVersions(
            final JvnAdvisory advisory,
            final JvnAdvisory.AffectedProduct product,
            final VulnerabilityAffects.Builder affectsBuilder) {
        boolean anyStructured = false;

        for (final String versionText : product.versionTexts()) {
            final JvnVersionParser.Result result = JvnVersionParser.parse(versionText, VERS_SCHEME);
            switch (result) {
                case JvnVersionParser.ExactVersion exact -> {
                    if (!hasVersion(affectsBuilder, exact.version())) {
                        affectsBuilder.addVersions(VulnerabilityAffectedVersions.newBuilder()
                                .setVersion(exact.version()));
                    }
                    anyStructured = true;
                }
                case JvnVersionParser.VersionRange range -> {
                    final String vers = range.vers().toString();
                    if (!hasRange(affectsBuilder, vers)) {
                        affectsBuilder.addVersions(VulnerabilityAffectedVersions.newBuilder()
                                .setRange(vers));
                    }
                    anyStructured = true;
                }
                case JvnVersionParser.Unparseable unparseable ->
                        LOGGER.debug("Unparseable version '{}' for {} ({}): {}",
                                versionText, product.cpe22(), advisory.jvnDbId(), unparseable.reason());
            }
        }

        // No structured version could be derived (empty, "all versions", or all unparseable).
        // The product is nonetheless declared affected by JVN, so emit an all-versions (wildcard)
        // range to preserve recall. This matches how NVD treats product-level CPEs.
        if (!anyStructured) {
            final String wildcard = Vers.builder(VERS_SCHEME)
                    .withConstraint(Comparator.WILDCARD, null)
                    .build()
                    .toString();
            if (!hasRange(affectsBuilder, wildcard)) {
                affectsBuilder.addVersions(VulnerabilityAffectedVersions.newBuilder().setRange(wildcard));
            }
        }
    }

    private static boolean hasVersion(final VulnerabilityAffects.Builder builder, final String version) {
        return builder.getVersionsList().stream()
                .filter(VulnerabilityAffectedVersions::hasVersion)
                .anyMatch(v -> v.getVersion().equals(version));
    }

    private static boolean hasRange(final VulnerabilityAffects.Builder builder, final String range) {
        return builder.getVersionsList().stream()
                .filter(VulnerabilityAffectedVersions::hasRange)
                .anyMatch(v -> v.getRange().equals(range));
    }

    private static Classification determineComponentType(final Cpe cpe) {
        return switch (cpe.getPart()) {
            case APPLICATION -> Classification.CLASSIFICATION_APPLICATION;
            case HARDWARE_DEVICE -> Classification.CLASSIFICATION_DEVICE;
            case OPERATING_SYSTEM -> Classification.CLASSIFICATION_OPERATING_SYSTEM;
            default -> Classification.CLASSIFICATION_NULL;
        };
    }

    private static List<VulnerabilityRating> parseRatings(final List<JvnAdvisory.Cvss> cvssList) {
        final var ratings = new ArrayList<VulnerabilityRating>();
        for (final JvnAdvisory.Cvss cvss : cvssList) {
            final VulnerabilityRating.Builder builder = VulnerabilityRating.newBuilder()
                    .setMethod(mapMethod(cvss.version()))
                    .setSeverity(mapSeverity(cvss.severity()));
            if (cvss.baseScore() != null) {
                builder.setScore(cvss.baseScore());
            }
            if (cvss.vector() != null) {
                builder.setVector(cvss.vector());
            }
            ratings.add(builder.build());
        }
        return ratings;
    }

    private static ScoreMethod mapMethod(final String version) {
        if (version == null) {
            return ScoreMethod.SCORE_METHOD_OTHER;
        }
        if (version.startsWith("2")) {
            return ScoreMethod.SCORE_METHOD_CVSSV2;
        }
        if (version.startsWith("3.1")) {
            return ScoreMethod.SCORE_METHOD_CVSSV31;
        }
        if (version.startsWith("3")) {
            return ScoreMethod.SCORE_METHOD_CVSSV3;
        }
        if (version.startsWith("4")) {
            return ScoreMethod.SCORE_METHOD_CVSSV4;
        }
        return ScoreMethod.SCORE_METHOD_OTHER;
    }

    private static Severity mapSeverity(final String severity) {
        if (severity == null) {
            return Severity.SEVERITY_UNKNOWN;
        }
        return switch (severity.toUpperCase(java.util.Locale.ROOT)) {
            case "CRITICAL" -> Severity.SEVERITY_CRITICAL;
            case "HIGH" -> Severity.SEVERITY_HIGH;
            case "MEDIUM", "MODERATE" -> Severity.SEVERITY_MEDIUM;
            case "LOW" -> Severity.SEVERITY_LOW;
            case "NONE" -> Severity.SEVERITY_NONE;
            default -> Severity.SEVERITY_UNKNOWN;
        };
    }
}
