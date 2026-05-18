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
package org.dependencytrack.vulndatasource.osv;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import io.github.nscuro.versatile.Vers;
import org.cyclonedx.proto.v1_7.Advisory;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Classification;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.OrganizationalContact;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.ScoreMethod;
import org.cyclonedx.proto.v1_7.Severity;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityAffectedVersions;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.cyclonedx.proto.v1_7.VulnerabilityCredits;
import org.cyclonedx.proto.v1_7.VulnerabilityRating;
import org.cyclonedx.proto.v1_7.VulnerabilityReference;
import org.dependencytrack.support.distrometadata.OsDistribution;
import org.dependencytrack.vulndatasource.osv.schema.Affected;
import org.dependencytrack.vulndatasource.osv.schema.Credit;
import org.dependencytrack.vulndatasource.osv.schema.DatabaseSpecific__1;
import org.dependencytrack.vulndatasource.osv.schema.EcosystemSpecific;
import org.dependencytrack.vulndatasource.osv.schema.Event;
import org.dependencytrack.vulndatasource.osv.schema.Osv;
import org.dependencytrack.vulndatasource.osv.schema.Package;
import org.dependencytrack.vulndatasource.osv.schema.Range;
import org.dependencytrack.vulndatasource.osv.schema.Reference;
import org.jspecify.annotations.Nullable;
import org.metaeffekt.core.security.cvss.CvssVector;
import org.metaeffekt.core.security.cvss.v2.Cvss2;
import org.metaeffekt.core.security.cvss.v3.Cvss3P0;
import org.metaeffekt.core.security.cvss.v3.Cvss3P1;
import org.metaeffekt.core.security.cvss.v4P0.Cvss4P0;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.github.nscuro.versatile.VersUtils.versFromOsvRange;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV2;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV3;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV31;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV4;
import static org.cyclonedx.proto.v1_7.Severity.SEVERITY_CRITICAL;
import static org.cyclonedx.proto.v1_7.Severity.SEVERITY_HIGH;
import static org.cyclonedx.proto.v1_7.Severity.SEVERITY_INFO;
import static org.cyclonedx.proto.v1_7.Severity.SEVERITY_LOW;
import static org.cyclonedx.proto.v1_7.Severity.SEVERITY_MEDIUM;
import static org.cyclonedx.proto.v1_7.Severity.SEVERITY_NONE;
import static org.cyclonedx.proto.v1_7.Severity.SEVERITY_UNKNOWN;

/**
 * @since 5.0.0
 */
final class ModelConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ModelConverter.class);
    private static final Pattern WILDCARD_VERS_PATTERN = Pattern.compile("^vers:\\w+/(\\*|>=0(\\.0)*)$");
    private static final Pattern CWE_PATTERN = Pattern.compile("^(?:CWE-)?(\\d+)\\b");
    private static final int MAX_TITLE_LEN = 255;

    private static final Map<String, Severity> SEVERITY_BY_NAME = Map.ofEntries(
            Map.entry("CRITICAL", SEVERITY_CRITICAL),
            Map.entry("HIGH", SEVERITY_HIGH),
            Map.entry("MEDIUM", SEVERITY_MEDIUM),
            Map.entry("MODERATE", SEVERITY_MEDIUM),
            Map.entry("LOW", SEVERITY_LOW),
            Map.entry("INFO", SEVERITY_INFO),
            Map.entry("NONE", SEVERITY_NONE));

    private static final Map<String, String> SOURCE_NAME_BY_PREFIX = Map.of(
            "GHSA", "GITHUB",
            "CVE", "NVD");

    private static final TypeReference<Map.Entry<String, String>> RANGE_EVENT_TYPE_REF = new TypeReference<>() {
    };

    private final ObjectMapper objectMapper;

    ModelConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    Bom convert(Osv osv, boolean isAliasSyncEnabled, String currentEcosystem) {
        final var bovBuilder = Bom.newBuilder();
        bovBuilder.addVulnerabilities(convertVulnerability(osv, isAliasSyncEnabled, currentEcosystem, bovBuilder));
        return bovBuilder.build();
    }

    private Vulnerability convertVulnerability(
            Osv osv,
            boolean isAliasSyncEnabled,
            String currentEcosystem,
            Bom.Builder bom) {
        final var vuln = Vulnerability.newBuilder();
        final String id = osv.getId();

        if (id != null) {
            vuln.setId(id);
            vuln.setSource(extractSource(id));
        }

        vuln.addProperties(
                Property.newBuilder()
                        .setName(CycloneDxPropertyNames.OSV_ECOSYSTEM)
                        .setValue(currentEcosystem));

        if (osv.getSummary() != null) {
            vuln.addProperties(
                    Property.newBuilder()
                            .setName(CycloneDxPropertyNames.VULN_TITLE)
                            .setValue(trimSummary(osv.getSummary())));
        }
        if (osv.getDetails() != null) {
            vuln.setDescription(osv.getDetails());
        }

        final Timestamp published = toTimestamp(osv.getPublished(), id, "published");
        if (published != null) {
            vuln.setPublished(published);
        }
        final Timestamp modified = toTimestamp(osv.getModified(), id, "modified");
        if (modified != null) {
            vuln.setUpdated(modified);
        }

        // CWEs and a fallback severity from OSV's top-level database_specific.
        Severity dbSeverity = SEVERITY_UNKNOWN;
        if (osv.getDatabaseSpecific() != null) {
            final Map<String, Object> dbProps = osv.getDatabaseSpecific().getAdditionalProperties();
            if (dbProps.get(DatabaseSpecificPropertyNames.CWE_IDS) instanceof final List<?> rawCwes) {
                for (final Object cwe : rawCwes) {
                    if (cwe instanceof final String cweString) {
                        final Integer cweId = parseCweString(cweString);
                        if (cweId != null) {
                            vuln.addCwes(cweId);
                        }
                    }
                }
            }
            if (dbProps.get(DatabaseSpecificPropertyNames.SEVERITY) instanceof final String dbSeverityString) {
                dbSeverity = convertSeverity(dbSeverityString);
            }
        }

        if (isAliasSyncEnabled) {
            vuln.addAllReferences(convertAliases(id, osv.getAliases()));
        }

        final VulnerabilityCredits credits = convertCredits(osv.getCredits());
        if (credits != null) {
            vuln.setCredits(credits);
        }

        vuln.addAllAdvisories(convertReferences(osv.getReferences()));

        Severity affectedSeverity = SEVERITY_UNKNOWN;
        final List<Affected> affected = osv.getAffected();
        if (affected != null && !affected.isEmpty()) {
            final var purlToBomRef = new HashMap<String, String>();
            final boolean isMalware = isOsvMalwareIdentifier(id);
            for (final Affected entry : affected) {
                final VulnerabilityAffects affects = convertAffected(id, entry, bom, purlToBomRef, isMalware);
                if (affects != null) {
                    vuln.addAffects(affects);
                }
            }

            affectedSeverity = highestAffectedSeverity(affected);
        }

        // Pick the strongest signal we have.
        // Malware advisories are always treated as critical.
        final Severity severity = !isOsvMalwareIdentifier(id)
                ? moreSevere(affectedSeverity, dbSeverity)
                : SEVERITY_CRITICAL;

        vuln.addAllRatings(convertRatings(osv, severity));

        return vuln.build();
    }

    private record DerivedCvss(ScoreMethod method, double score, Severity severity, String vector) {
    }

    private static @Nullable DerivedCvss deriveCvss(@Nullable String vectorString) {
        if (vectorString == null || vectorString.isBlank()) {
            return null;
        }

        final CvssVector cvss = CvssVector.parseVector(vectorString, true);
        if (cvss == null || !cvss.isBaseFullyDefined()) {
            return null;
        }

        final double score = cvss.getBakedScores().getBaseScore();
        final String stored = cvss instanceof Cvss2
                ? "(" + cvss + ")"
                : cvss.toString();
        return switch (cvss) {
            case Cvss4P0 _ -> new DerivedCvss(SCORE_METHOD_CVSSV4, score, scoreToSeverityCvssV4(score), stored);
            case Cvss3P1 _ -> new DerivedCvss(SCORE_METHOD_CVSSV31, score, scoreToSeverityCvssV3(score), stored);
            case Cvss3P0 _ -> new DerivedCvss(SCORE_METHOD_CVSSV3, score, scoreToSeverityCvssV3(score), stored);
            case Cvss2 _ -> new DerivedCvss(SCORE_METHOD_CVSSV2, score, scoreToSeverityCvssV2(score), stored);
            default -> null;
        };
    }

    // https://www.first.org/cvss/v4-0/specification-document#Qualitative-Severity-Rating-Scale
    private static Severity scoreToSeverityCvssV4(double score) {
        if (score >= 9) {
            return SEVERITY_CRITICAL;
        }
        if (score >= 7) {
            return SEVERITY_HIGH;
        }
        if (score >= 4) {
            return SEVERITY_MEDIUM;
        }
        if (score >= 0.1) {
            return SEVERITY_LOW;
        }
        if (score == 0) {
            return SEVERITY_NONE;
        }

        return SEVERITY_UNKNOWN;
    }

    // https://www.first.org/cvss/v3-1/specification-document#Qualitative-Severity-Rating-Scale
    private static Severity scoreToSeverityCvssV3(double score) {
        if (score >= 9) {
            return SEVERITY_CRITICAL;
        }
        if (score >= 7) {
            return SEVERITY_HIGH;
        }
        if (score >= 4) {
            return SEVERITY_MEDIUM;
        }
        if (score > 0) {
            return SEVERITY_LOW;
        }
        if (score == 0) {
            return SEVERITY_NONE;
        }

        return SEVERITY_UNKNOWN;
    }

    // https://nvd.nist.gov/vuln-metrics/cvss
    private static Severity scoreToSeverityCvssV2(double score) {
        if (score >= 7) {
            return SEVERITY_HIGH;
        }
        if (score >= 4) {
            return SEVERITY_MEDIUM;
        }
        if (score > 0) {
            return SEVERITY_LOW;
        }

        return SEVERITY_UNKNOWN;
    }

    private static Severity convertSeverity(@Nullable String severity) {
        if (severity == null) {
            return SEVERITY_UNKNOWN;
        }

        return SEVERITY_BY_NAME.getOrDefault(severity.toUpperCase(Locale.ROOT), SEVERITY_UNKNOWN);
    }

    private static Severity moreSevere(Severity a, Severity b) {
        return severityPriority(a) >= severityPriority(b) ? a : b;
    }

    private static int severityPriority(Severity severity) {
        if (severity == SEVERITY_UNKNOWN || severity == Severity.UNRECOGNIZED) {
            return Integer.MIN_VALUE;
        }

        return -severity.getNumber();
    }

    private static Severity highestAffectedSeverity(List<Affected> affected) {
        Severity highest = SEVERITY_UNKNOWN;
        for (final Affected entry : affected) {
            highest = moreSevere(highest, severityForAffected(entry));
        }

        return highest;
    }

    private static Severity severityForAffected(Affected entry) {
        final EcosystemSpecific ecosystemSpecific = entry.getEcosystemSpecific();
        if (ecosystemSpecific != null
                && ecosystemSpecific.getAdditionalProperties().get(DatabaseSpecificPropertyNames.SEVERITY) instanceof final String ecosystemSeverity) {
            return convertSeverity(ecosystemSeverity);
        }

        return SEVERITY_UNKNOWN;
    }

    private static List<VulnerabilityRating> convertRatings(Osv osv, Severity fallbackSeverity) {
        final List<org.dependencytrack.vulndatasource.osv.schema.Severity> osvSeverities = osv.getSeverity();
        if (osvSeverities == null || osvSeverities.isEmpty()) {
            return List.of(
                    VulnerabilityRating.newBuilder()
                            .setSeverity(fallbackSeverity)
                            .build());
        }

        final var ratings = new ArrayList<VulnerabilityRating>(osvSeverities.size());
        for (final org.dependencytrack.vulndatasource.osv.schema.Severity osvSeverity : osvSeverities) {
            // https://ossf.github.io/osv-schema/#severitytype-field
            if (osvSeverity.getType() != org.dependencytrack.vulndatasource.osv.schema.Severity.Type.CVSS_V_2
                    && osvSeverity.getType() != org.dependencytrack.vulndatasource.osv.schema.Severity.Type.CVSS_V_3
                    && osvSeverity.getType() != org.dependencytrack.vulndatasource.osv.schema.Severity.Type.CVSS_V_4) {
                continue;
            }

            final String vector = osvSeverity.getScore();
            final DerivedCvss derived = deriveCvss(vector);
            if (derived == null) {
                LOGGER.warn("Failed to parse CVSS vector: {}", vector);
                continue;
            }

            ratings.add(
                    VulnerabilityRating.newBuilder()
                            .setMethod(derived.method())
                            .setScore(derived.score())
                            .setSeverity(derived.severity())
                            .setVector(derived.vector())
                            .build());
        }

        if (ratings.isEmpty()) {
            return List.of(
                    VulnerabilityRating.newBuilder()
                            .setSeverity(fallbackSeverity)
                            .build());
        }

        return ratings;
    }

    private static List<Advisory> convertReferences(@Nullable List<Reference> references) {
        if (references == null || references.isEmpty()) {
            return List.of();
        }

        final var advisories = new ArrayList<Advisory>(references.size());
        for (final Reference reference : references) {
            if (reference.getUrl() == null || reference.getUrl().isBlank()) {
                continue;
            }

            advisories.add(
                    Advisory.newBuilder()
                            .setUrl(reference.getUrl())
                            .build());
        }

        return advisories;
    }

    private static List<VulnerabilityReference> convertAliases(
            @Nullable String selfId,
            @Nullable List<String> aliases) {
        if (aliases == null || aliases.isEmpty()) {
            return List.of();
        }

        final var result = new ArrayList<VulnerabilityReference>(aliases.size());
        for (final String alias : aliases) {
            if (alias == null || alias.isBlank() || alias.equals(selfId)) {
                continue;
            }

            result.add(
                    VulnerabilityReference.newBuilder()
                            .setId(alias)
                            .setSource(extractSource(alias))
                            .build());
        }

        return result;
    }

    private @Nullable VulnerabilityAffects convertAffected(
            @Nullable String vulnId,
            Affected entry,
            Bom.Builder bom,
            Map<String, String> purlToBomRef,
            boolean isMalware) {
        final Package pkg = entry.getPackage();
        if (pkg == null) {
            return null;
        }

        final String rawPurl = pkg.getPurl();
        if (rawPurl == null) {
            LOGGER.debug("affected node for vulnerability {} does not provide a PURL; Skipping", vulnId);
            return null;
        }

        final PackageURL parsedPurl;
        try {
            parsedPurl = new PackageURL(rawPurl);
        } catch (MalformedPackageURLException ex) {
            LOGGER.warn("Failed to parse PURL '{}' from affected node for vulnerability {}", rawPurl, vulnId, ex);
            return null;
        }

        final String purl = tryEnrichDistroQualifier(parsedPurl, pkg.getEcosystem(), vulnId);

        final String bomRef = purlToBomRef.computeIfAbsent(purl, p -> {
            final Component component = newComponent(pkg, p);
            bom.addComponents(component);
            return component.getBomRef();
        });

        return VulnerabilityAffects.newBuilder()
                .setRef(bomRef)
                .addAllVersions(convertVersions(entry, isMalware))
                .build();
    }

    private static String tryEnrichDistroQualifier(
            PackageURL purl,
            @Nullable String ecosystem,
            @Nullable String vulnId) {
        // Some PURLs already include the distro qualifier, e.g. "pkg:deb/ubuntu/php7.0?distro=xenial".
        // For others, infer it from the OSV ecosystem string, e.g. "Debian:13".
        final Map<String, String> qualifiers = purl.getQualifiers();
        if (qualifiers != null && qualifiers.get("distro") != null) {
            return purl.toString();
        }

        final OsDistribution distro = OsvEcosystems.toOsDistribution(ecosystem);
        if (distro == null) {
            return purl.toString();
        }

        try {
            return purl.toBuilder()
                    .withQualifier("distro", distro.purlQualifierValue())
                    .build()
                    .toString();
        } catch (MalformedPackageURLException e) {
            LOGGER.warn(
                    "Failed to add distro qualifier to PURL '{}' for vulnerability {}; Using original PURL",
                    purl, vulnId, e);
            return purl.toString();
        }
    }

    private static Component newComponent(Package pkg, String purl) {
        final UUID uuid = UUID.nameUUIDFromBytes(purl.getBytes(StandardCharsets.UTF_8));
        final var builder = Component.newBuilder()
                .setBomRef(uuid.toString())
                .setType(Classification.CLASSIFICATION_LIBRARY)
                .setPurl(purl);
        if (pkg.getName() != null) {
            builder.setName(pkg.getName());
        }

        return builder.build();
    }

    private List<VulnerabilityAffectedVersions> convertVersions(Affected entry, boolean isMalware) {
        final List<Range> ranges = entry.getRanges();
        final var parsedRanges = new ArrayList<VulnerabilityAffectedVersions>();
        if (ranges != null) {
            final String ecosystem = entry.getPackage() != null ? entry.getPackage().getEcosystem() : null;
            for (final Range range : ranges) {
                parsedRanges.addAll(convertRange(range, ecosystem, entry.getDatabaseSpecific()));
            }
        }

        // OSV typically provides BOTH ranges (introduced/fixed events) and a redundant `versions` array
        // expanded from those ranges. Consume the ranges by default, and fall back to discrete versions
        // only when no usable range was parsed.
        //
        // For malware advisories (MAL-*), also fall back to discrete versions when only wildcard ranges
        // (e.g. `>=0`) survived. Such records pair a wildcard range with a precise list of malicious
        // versions and trusting the wildcard would flag every legitimate release as malware. See
        // https://osv-vulnerabilities.storage.googleapis.com/npm/MAL-2023-995.json.
        //
        // Outside of malware, wildcard-only ranges are authoritative ("all versions affected"), even
        // when the advisory enumerates known versions alongside them. This is common for unfixed distro
        // CVEs, where Debian / Ubuntu list every historical release of a source package under
        // `introduced=0`. Expanding those into per-version VulnerableSoftware records produces tens of
        // thousands of redundant rows per advisory without adding matching information.
        final List<String> exactVersions = entry.getVersions();
        final boolean noUsableRange = parsedRanges.isEmpty();
        final boolean malwareWildcardOnly = isMalware
                && !parsedRanges.isEmpty()
                && parsedRanges.stream()
                        .map(VulnerabilityAffectedVersions::getRange)
                        .allMatch(WILDCARD_VERS_PATTERN.asPredicate());
        if ((noUsableRange || malwareWildcardOnly)
                && exactVersions != null
                && !exactVersions.isEmpty()) {
            final var fallback = new ArrayList<VulnerabilityAffectedVersions>(exactVersions.size());
            for (final String version : exactVersions) {
                fallback.add(
                        VulnerabilityAffectedVersions.newBuilder()
                                .setVersion(version)
                                .build());
            }

            return fallback;
        }

        return parsedRanges;
    }

    private List<VulnerabilityAffectedVersions> convertRange(
            Range range,
            @Nullable String ecosystem,
            @Nullable DatabaseSpecific__1 databaseSpecific) {
        final Range.Type rangeType = range.getType();
        if (rangeType == null || rangeType == Range.Type.GIT || ecosystem == null) {
            // CycloneDX `range` MUST be valid `vers` syntax. OSV `GIT` ranges contain commit hashes,
            // not versions, so they cannot be expressed as a version range and are therefore skipped.
            return List.of();
        }

        final List<Event> events = range.getEvents();
        if (events == null || events.isEmpty()) {
            return List.of();
        }

        final List<Map.Entry<String, String>> rangeEvents = new ArrayList<>(events.size());
        for (final Event event : events) {
            rangeEvents.add(objectMapper.convertValue(event, RANGE_EVENT_TYPE_REF));
        }

        final boolean lastIsUpperBound = isUpperBound(rangeEvents.getLast().getKey());
        final Map<String, Object> dbProps = !lastIsUpperBound && databaseSpecific != null
                ? databaseSpecific.getAdditionalProperties()
                : null;

        try {
            final Vers vers = versFromOsvRange(rangeType.value(), ecosystem, rangeEvents, dbProps);
            return List.of(
                    VulnerabilityAffectedVersions.newBuilder()
                            .setRange(vers.toString())
                            .build());
        } catch (Exception e) {
            LOGGER.debug("Exception while parsing OSV version range.", e);
            return List.of();
        }
    }

    private static boolean isUpperBound(String eventKey) {
        return "fixed".equals(eventKey) || "limit".equals(eventKey) || "last_affected".equals(eventKey);
    }

    private static @Nullable VulnerabilityCredits convertCredits(@Nullable List<Credit> credits) {
        if (credits == null || credits.isEmpty()) {
            return null;
        }

        final var builder = VulnerabilityCredits.newBuilder();
        for (final Credit credit : credits) {
            final OrganizationalContact contact = convertCredit(credit);
            if (contact != null) {
                builder.addIndividuals(contact);
            }
        }

        return builder.getIndividualsCount() == 0 ? null : builder.build();
    }

    private static @Nullable OrganizationalContact convertCredit(Credit credit) {
        if (credit == null) {
            return null;
        }

        final var builder = OrganizationalContact.newBuilder();
        if (credit.getName() != null) {
            builder.setName(credit.getName());
        }

        final List<String> contacts = credit.getContact();
        if (contacts != null) {
            contacts.stream()
                    .map(ModelConverter::extractEmail)
                    .filter(email -> email != null && !email.isEmpty())
                    .findFirst()
                    .ifPresent(builder::setEmail);
        }

        if (!builder.hasName() && !builder.hasEmail()) {
            return null;
        }

        return builder.build();
    }

    private static @Nullable String extractEmail(@Nullable String contact) {
        if (contact == null || contact.isBlank()) {
            return null;
        }

        final String trimmed = contact.trim();
        final URI uri;
        try {
            uri = new URI(trimmed);
        } catch (URISyntaxException e) {
            return null;
        }

        final String scheme = uri.getScheme();
        if (scheme == null) {
            return trimmed.indexOf('@') > 0 ? trimmed : null;
        }
        if ("mailto".equalsIgnoreCase(scheme)) {
            final String address = uri.getSchemeSpecificPart();
            return address != null ? address.trim() : null;
        }

        return null;
    }

    static String trimSummary(@Nullable String summary) {
        if (summary == null) {
            return null;
        }

        if (summary.length() > MAX_TITLE_LEN) {
            return summary.substring(0, MAX_TITLE_LEN - 2) + "..";
        }

        return summary;
    }

    private static Source extractSource(String vulnId) {
        final String prefix = vulnId.split("-", 2)[0];
        final String name = SOURCE_NAME_BY_PREFIX.getOrDefault(prefix, "OSV");
        return Source.newBuilder().setName(name).build();
    }

    private static boolean isOsvMalwareIdentifier(@Nullable String osvId) {
        return osvId != null && osvId.startsWith("MAL-");
    }

    private static @Nullable Integer parseCweString(@Nullable String cweString) {
        if (cweString == null || cweString.isBlank()) {
            return null;
        }

        final Matcher matcher = CWE_PATTERN.matcher(cweString.trim());
        if (!matcher.find()) {
            return null;
        }

        try {
            return Integer.valueOf(matcher.group(1));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static @Nullable Timestamp toTimestamp(
            @Nullable Date date,
            @Nullable String advisoryId,
            String fieldName) {
        if (date == null) {
            return null;
        }

        try {
            return Timestamps.fromMillis(date.toInstant().toEpochMilli());
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Ignoring invalid {} timestamp for advisory {}", fieldName, advisoryId, e);
            return null;
        }
    }

}
