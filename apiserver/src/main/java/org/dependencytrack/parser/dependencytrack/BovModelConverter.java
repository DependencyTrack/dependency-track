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
package org.dependencytrack.parser.dependencytrack;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.google.protobuf.util.Timestamps;
import io.github.nscuro.versatile.Constraint;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import io.github.nscuro.versatile.spi.InvalidVersionException;
import io.github.nscuro.versatile.spi.Version;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.ScoreMethod;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.VulnerabilityAffectedVersions;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.cyclonedx.proto.v1_7.VulnerabilityRating;
import org.cyclonedx.proto.v1_7.VulnerabilityReference;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.util.PurlUtil;
import org.dependencytrack.util.VulnerabilityUtil;
import org.jspecify.annotations.Nullable;
import org.metaeffekt.core.security.cvss.CvssVector;
import org.metaeffekt.core.security.cvss.processor.BakedCvssVectorScores;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.owasp.riskrating.MissingFactorException;
import us.springett.owasp.riskrating.OwaspRiskRating;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import static io.github.nscuro.versatile.version.KnownVersioningSchemes.SCHEME_GENERIC;
import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV2;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV3;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV31;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV4;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_OWASP;

public final class BovModelConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(BovModelConverter.class);
    private static final Pattern EFFECTIVELY_ZERO_PATTERN = Pattern.compile("^0(\\.0)*$");
    static final String TITLE_PROPERTY_NAME = "dependency-track:vuln:title";

    private BovModelConverter() {
    }

    public static Vulnerability convert(
            final Bom bov,
            final org.cyclonedx.proto.v1_7.Vulnerability cdxVuln,
            final boolean isAliasSyncEnabled) {
        if (cdxVuln == null) {
            return null;
        }

        final var vuln = new Vulnerability();
        if (cdxVuln.hasId()) {
            vuln.setSource(extractSource(cdxVuln.getId(), cdxVuln.getSource()));
        }
        vuln.setVulnId(cdxVuln.getId());
        if (cdxVuln.getPropertiesCount() != 0) {
            var titleProperty = cdxVuln.getProperties(0);
            if (titleProperty.getName().equals(TITLE_PROPERTY_NAME) && titleProperty.hasValue()) {
                vuln.setTitle(StringUtils.abbreviate(titleProperty.getValue(), 255));
            }
        }
        if (cdxVuln.hasDescription()) {
            vuln.setDescription(cdxVuln.getDescription());
        }
        if (cdxVuln.hasDetail()) {
            vuln.setDetail(cdxVuln.getDetail());
        }
        if (cdxVuln.hasRecommendation()) {
            vuln.setRecommendation(cdxVuln.getRecommendation());
        }
        if (cdxVuln.hasPublished()) {
            vuln.setPublished(new Date(Timestamps.toMillis(cdxVuln.getPublished())));
        }
        if (cdxVuln.hasUpdated()) {
            vuln.setUpdated(new Date(Timestamps.toMillis(cdxVuln.getUpdated())));
        }
        if (cdxVuln.hasCreated()) {
            vuln.setCreated(new Date(Timestamps.toMillis(cdxVuln.getCreated())));
        }
        if (cdxVuln.hasRejected()) {
            vuln.setRejected(new Date(Timestamps.toMillis(cdxVuln.getRejected())));
        }
        if (cdxVuln.hasCredits()) {
            vuln.setCredits(String.join(", ", cdxVuln.getCredits().toString()));
        }

        // External links: collect from both BOM-level external references and the
        // vulnerability's advisories so neither source is silently dropped.
        final StringBuilder sb = new StringBuilder();
        final Consumer<String> appendLink = url ->
                sb.append("* [").append(url).append("](").append(url).append(")\n");
        bov.getExternalReferencesList().forEach(ref -> appendLink.accept(ref.getUrl()));
        cdxVuln.getAdvisoriesList().forEach(advisory -> appendLink.accept(advisory.getUrl()));
        if (!sb.isEmpty()) {
            vuln.setReferences(sb.toString());
        }

        cdxVuln.getCwesList().stream()
                .map(CweResolver.getInstance()::lookup)
                .filter(Objects::nonNull)
                .forEach(vuln::addCwe);

        final List<VulnerabilityRating> prioritizedRatings = cdxVuln.getRatingsList().stream()
                .sorted(compareRatings(cdxVuln.getSource()))
                .toList();

        // Apply ratings in their prioritized order, ensuring that only one rating per method is applied.
        // Because DT does not track CVSSv3 and CVSSv3.1 separately, they are considered the same here.
        final var appliedMethods = new HashSet<ScoreMethod>();
        for (final VulnerabilityRating rating : prioritizedRatings) {
            if (!rating.hasMethod()) {
                // We'll not be able to populate Vulnerability fields correctly if
                // we don't know what method was used to produce the rating.
                continue;
            }

            if (!appliedMethods.contains(SCORE_METHOD_CVSSV4) && (rating.getMethod().equals(SCORE_METHOD_CVSSV4))) {
                vuln.setCvssV4Vector(trimToNull(rating.getVector()));
                vuln.setCvssV4Score(BigDecimal.valueOf(rating.getScore()));
                if (rating.hasVector()) {
                    final CvssVector cvss = CvssVector.parseVector(rating.getVector(), true);
                    if (cvss != null && cvss.isBaseFullyDefined()) {
                        if (rating.getScore() == 0.0) {
                            vuln.setCvssV4Score(BigDecimal.valueOf(cvss.getBakedScores().getBaseScore()));
                        }
                    } else {
                        LOGGER.debug("Skipping CVSSv4 score derivation: vector '{}' could not be parsed or has incomplete base metrics", rating.getVector());
                    }
                }
                appliedMethods.add(SCORE_METHOD_CVSSV4);
            }
            if (!appliedMethods.contains(SCORE_METHOD_CVSSV3)
                    && (rating.getMethod().equals(SCORE_METHOD_CVSSV3)
                    || rating.getMethod().equals(SCORE_METHOD_CVSSV31))) {
                vuln.setCvssV3Vector(trimToNull(rating.getVector()));
                vuln.setCvssV3BaseScore(BigDecimal.valueOf(rating.getScore()));
                if (rating.hasVector()) {
                    final CvssVector cvss = CvssVector.parseVector(rating.getVector(), true);
                    if (cvss != null && cvss.isBaseFullyDefined()) {
                        final BakedCvssVectorScores scores = cvss.getBakedScores();
                        vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(scores.getImpactScore()));
                        vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(scores.getExploitabilityScore()));
                        if (rating.getScore() == 0.0) {
                            vuln.setCvssV3BaseScore(BigDecimal.valueOf(scores.getBaseScore()));
                        }
                    } else {
                        LOGGER.debug("Skipping CVSSv3 sub-score derivation: vector '{}' could not be parsed or has incomplete base metrics", rating.getVector());
                    }
                }
                appliedMethods.add(SCORE_METHOD_CVSSV3);
            }
            if (!appliedMethods.contains(SCORE_METHOD_CVSSV2) && rating.getMethod().equals(SCORE_METHOD_CVSSV2)) {
                vuln.setCvssV2Vector(trimToNull(rating.getVector()));
                vuln.setCvssV2BaseScore(BigDecimal.valueOf(rating.getScore()));
                if (rating.hasVector()) {
                    final CvssVector cvss = CvssVector.parseVector(rating.getVector(), true);
                    if (cvss != null && cvss.isBaseFullyDefined()) {
                        final BakedCvssVectorScores scores = cvss.getBakedScores();
                        vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(scores.getImpactScore()));
                        vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(scores.getExploitabilityScore()));
                        if (rating.getScore() == 0.0) {
                            vuln.setCvssV2BaseScore(BigDecimal.valueOf(scores.getBaseScore()));
                        }
                    } else {
                        LOGGER.debug("Skipping CVSSv2 sub-score derivation: vector '{}' could not be parsed or has incomplete base metrics", rating.getVector());
                    }
                }
                appliedMethods.add(SCORE_METHOD_CVSSV2);
            }
            if (!appliedMethods.contains(SCORE_METHOD_OWASP) && rating.getMethod().equals(ScoreMethod.SCORE_METHOD_OWASP)) {
                try {
                    final OwaspRiskRating orr = OwaspRiskRating.fromVector(rating.getVector());
                    final us.springett.owasp.riskrating.Score orrScore = orr.calculateScore();
                    vuln.setOwaspRRVector(trimToNull(rating.getVector()));
                    vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(orrScore.getLikelihoodScore()));
                    vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(orrScore.getBusinessImpactScore()));
                    vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(orrScore.getTechnicalImpactScore()));
                    appliedMethods.add(SCORE_METHOD_OWASP);
                } catch (IllegalArgumentException | MissingFactorException e) {
                    // Ignore
                }
            }
        }
        vuln.setSeverity(VulnerabilityUtil.getSeverity(
                vuln.getSeverity(),
                vuln.getCvssV2BaseScore(),
                vuln.getCvssV3BaseScore(),
                vuln.getCvssV4Score(),
                vuln.getOwaspRRLikelihoodScore(),
                vuln.getOwaspRRTechnicalImpactScore(),
                vuln.getOwaspRRBusinessImpactScore()
        ));

        // There can be cases where ratings do not have a known method, and the source only assigned
        // a severity. Such ratings are inferior to those with proper method and vector, but we'll use
        // them if no better option is available.
        if (appliedMethods.isEmpty() && vuln.getSeverity() == Severity.UNASSIGNED) {
            // Pick the first rating that provides a severity, and apply that.
            prioritizedRatings.stream()
                    .filter(VulnerabilityRating::hasSeverity)
                    .findFirst()
                    .map(rating -> switch (rating.getSeverity()) {
                        case SEVERITY_CRITICAL -> Severity.CRITICAL;
                        case SEVERITY_HIGH -> Severity.HIGH;
                        case SEVERITY_MEDIUM -> Severity.MEDIUM;
                        case SEVERITY_LOW -> Severity.LOW;
                        default -> Severity.UNASSIGNED;
                    })
                    .ifPresent(vuln::setSeverity);
        }

        if (isAliasSyncEnabled && !cdxVuln.getReferencesList().isEmpty()) {
            vuln.setAliases(cdxVuln.getReferencesList().stream()
                    .map(alias -> convert(cdxVuln, alias))
                    .filter(Objects::nonNull)
                    .toList());
        }

        // EPSS is an additional enrichment that no scanner currently provides.
        // TODO: Add mapping of EPSS score and percentile when needed.

        return vuln;
    }

    public static List<VulnerableSoftware> extractVulnerableSoftware(final Bom bov) {
        final org.cyclonedx.proto.v1_7.Vulnerability vuln = bov.getVulnerabilities(0);
        if (vuln.getAffectsCount() == 0) {
            return Collections.emptyList();
        }

        final var componentByBomRef = new HashMap<String, Component>();
        final var vsList = new ArrayList<VulnerableSoftware>();

        for (final VulnerabilityAffects bovVulnAffects : vuln.getAffectsList()) {
            final Component component = componentByBomRef.computeIfAbsent(
                    bovVulnAffects.getRef(),
                    bomRef -> bov.getComponentsList().stream()
                            .filter(c -> bomRef.equals(c.getBomRef()))
                            .findAny()
                            .orElse(null));
            if (component == null) {
                LOGGER.warn(
                        "No component in the BOV for {} is matching the BOM ref '{}' of the affects node; Skipping",
                        vuln.getId(), bovVulnAffects.getRef());
                continue;
            }

            for (final VulnerabilityAffectedVersions affectedVersions : bovVulnAffects.getVersionsList()) {
                if (affectedVersions.hasVersion()) {
                    vsList.addAll(convertAffectedVersion(vuln.getId(), affectedVersions.getVersion(), component));
                }
                if (affectedVersions.hasRange()) {
                    vsList.addAll(convertAffectedVersionRange(vuln.getId(), affectedVersions.getRange(), component));
                }
            }
        }

        return vsList.stream()
                .filter(distinctIgnoringDatastoreIdentity())
                .toList();
    }

    private static @Nullable VulnerabilityAlias convert(
            org.cyclonedx.proto.v1_7.Vulnerability cycloneVuln,
            VulnerabilityReference cycloneAlias) {
        final var vulnSource = Vulnerability.Source.ofName(cycloneVuln.getSource().getName());
        if (vulnSource == null || vulnSource == Vulnerability.Source.UNKNOWN) {
            return null;
        }

        final var aliasSource = Vulnerability.Source.ofName(cycloneAlias.getSource().getName());
        if (aliasSource == null || aliasSource == Vulnerability.Source.UNKNOWN) {
            return null;
        }

        final var alias = new VulnerabilityAlias();
        switch (vulnSource) {
            case GITHUB -> alias.setGhsaId(cycloneVuln.getId());
            case INTERNAL -> alias.setInternalId(cycloneVuln.getId());
            case NVD -> alias.setCveId(cycloneVuln.getId());
            case OSSINDEX -> alias.setSonatypeId(cycloneVuln.getId());
            case OSV -> alias.setOsvId(cycloneVuln.getId());
            case SNYK -> alias.setSnykId(cycloneVuln.getId());
            case VULNDB -> alias.setVulnDbId(cycloneVuln.getId());
            // Source of the vulnerability itself has been validated before,
            // so this scenario is highly unlikely to ever happen. Including
            // it here to make linters happy.
            default -> throw new IllegalArgumentException(
                    "Invalid vulnerability source %s".formatted(vulnSource));
        }

        switch (aliasSource) {
            case GITHUB -> alias.setGhsaId(cycloneAlias.getId());
            case INTERNAL -> alias.setInternalId(cycloneAlias.getId());
            case NVD -> alias.setCveId(cycloneAlias.getId());
            case OSSINDEX -> alias.setSonatypeId(cycloneAlias.getId());
            case OSV -> alias.setOsvId(cycloneAlias.getId());
            case SNYK -> alias.setSnykId(cycloneAlias.getId());
            case VULNDB -> alias.setVulnDbId(cycloneAlias.getId());
            default -> throw new IllegalArgumentException(
                    "Invalid source %s for alias %s".formatted(aliasSource, cycloneAlias.getId()));
        }

        return alias;
    }

    static Vulnerability.Source extractSource(String vulnId, Source source) {
        var resolvedSource = Vulnerability.Source.ofName(source.getName());
        if (resolvedSource != null) {
            return resolvedSource;
        }

        resolvedSource = Vulnerability.Source.ofVulnId(vulnId);
        if (resolvedSource != null) {
            return resolvedSource;
        }

        return Vulnerability.Source.UNKNOWN;
    }

    /**
     * Determines the priority of {@link ScoreMethod}s, as used by {@link #compareRatings(Source)}.
     * <p>
     * A lower number signals a higher priority.
     *
     * @return Priority of the {@link ScoreMethod}
     */
    private static int scoreMethodPriority(final ScoreMethod method) {
        return switch (method) {
            case SCORE_METHOD_CVSSV4 -> 0;
            case SCORE_METHOD_CVSSV31 -> 1;
            case SCORE_METHOD_CVSSV3 -> 2;
            case SCORE_METHOD_CVSSV2 -> 3;
            case SCORE_METHOD_OWASP -> 4;
            default -> 999;
        };
    }

    /**
     * Vulnerabilities can have multiple risk ratings of the same type, and by multiple sources,
     * but DT currently only supports one per type.
     */
    private static Comparator<VulnerabilityRating> compareRatings(final Source vulnSource) {
        return (left, right) -> {
            // Prefer ratings from the vulnerability's authoritative source.
            if (left.getSource().getName().equals(vulnSource.getName()) && !right.getSource().getName().equals(vulnSource.getName())) {
                return -1; // left wins
            } else if (!left.getSource().getName().equals(vulnSource.getName()) && right.getSource().getName().equals(vulnSource.getName())) {
                return 1; // right wins
            }

            // Prefer specified method over no / unknown methods.
            if (left.hasMethod() && !right.hasMethod()) {
                return -1; // left wins
            } else if (!left.hasMethod() && right.hasMethod()) {
                return 1; // right wins
            }

            // Prefer ratings with vector
            if (left.hasVector() && !right.hasVector()) {
                return -1; // left wins
            } else if (!left.hasVector() && right.hasVector()) {
                return 1; // right wins
            }

            // Leave the final decision up to the respective method's priorities.
            return Integer.compare(
                    scoreMethodPriority(left.getMethod()),
                    scoreMethodPriority(right.getMethod())
            );
        };
    }

    private static List<VulnerableSoftware> convertAffectedVersion(
            String vulnId,
            String affectedVersion,
            Component affectedComponent) {
        return createVulnerableSoftware(vulnId, affectedComponent, affectedVersion, null, null, null, null);
    }

    private static List<VulnerableSoftware> convertAffectedVersionRange(
            String vulnId,
            String affectedVersionRange,
            Component affectedComponent) {
        final List<VulnerableSoftware> vsList = new ArrayList<>();
        final List<Vers> versList;
        try {
            versList = convertRangeToVersList(affectedVersionRange);
        } catch (VersException e) {
            LOGGER.warn(
                    "Failed to parse vers range from '{}' for {}",
                    affectedVersionRange, vulnId, e);
            return vsList;
        }

        for (final Vers vers : versList) {
            if (vers.constraints().isEmpty()) {
                LOGGER.debug(
                        "Vers range '{}' (parsed: {}) for {} does not contain any constraints; Skipping",
                        affectedVersionRange, vers, vulnId);
                continue;
            } else if (vers.constraints().size() == 1) {
                final var versConstraint = vers.constraints().getFirst();
                if (versConstraint.comparator() == io.github.nscuro.versatile.Comparator.WILDCARD
                        || (versConstraint.comparator() == io.github.nscuro.versatile.Comparator.GREATER_THAN_OR_EQUAL
                        && isEffectivelyZero(versConstraint.version()))) {
                    // Wildcards and ">=0" mean "all versions".
                    // Represent as versionStartIncluding=0 to use the range matching logic.
                    vsList.addAll(createVulnerableSoftware(
                            vulnId, affectedComponent, null, "0", null, null, null));
                    continue;
                }
                if (versConstraint.comparator() == io.github.nscuro.versatile.Comparator.GREATER_THAN
                        && isEffectivelyZero(versConstraint.version())) {
                    // ">0" means all versions except version 0.
                    vsList.addAll(createVulnerableSoftware(
                            vulnId, affectedComponent, null, null, "0", null, null));
                    continue;
                }
                if (versConstraint.comparator() == io.github.nscuro.versatile.Comparator.EQUAL) {
                    vsList.addAll(convertAffectedVersion(
                            vulnId, versConstraint.version().toString(), affectedComponent));
                    continue;
                }
            }
            vsList.addAll(convertVersToVulnerableSoftware(vers, vulnId, affectedComponent));
        }
        return vsList;
    }

    static List<Vers> convertRangeToVersList(String range) {
        try {
            return Vers.parse(range).validate().split();
        } catch (InvalidVersionException e) {
            String[] rangeParts = range.split(":", 2);
            if (SCHEME_GENERIC.equals(rangeParts[0])) {
                LOGGER.warn("""
                        Range '{}' could not be parsed because one or more versions \
                        do not comply with the versioning scheme's rules; Skipping""", range, e);
                return Collections.emptyList();
            }

            LOGGER.warn("""
                    Range '{}' could not be parsed because one or more versions \
                    do not comply with the versioning scheme's rules; \
                    Falling back to versioning scheme 'generic' instead""", range, e);
            String[] versions = rangeParts[1].split("/", 2);
            var genericRange = rangeParts[0] + ":" + SCHEME_GENERIC + "/" + versions[1];
            return convertRangeToVersList(genericRange);
        }
    }

    private static List<VulnerableSoftware> convertVersToVulnerableSoftware(
            Vers vers,
            String vulnId,
            Component affectedComponent) {
        final var vsList = new ArrayList<VulnerableSoftware>();
        final var exactVersions = new ArrayList<String>();

        String versionStartIncluding = null;
        String versionStartExcluding = null;
        String versionEndIncluding = null;
        String versionEndExcluding = null;

        for (final Constraint constraint : vers.constraints()) {
            if (constraint.version() == null) {
                continue;
            }

            final String versionStr = constraint.version().toString();

            switch (constraint.comparator()) {
                case GREATER_THAN -> versionStartExcluding = versionStr;
                case GREATER_THAN_OR_EQUAL -> {
                    // Normalize ">=0" variants to "0" for consistency.
                    versionStartIncluding = isEffectivelyZero(constraint.version()) ? "0" : versionStr;
                }
                case LESS_THAN_OR_EQUAL -> versionEndIncluding = versionStr;
                case LESS_THAN -> versionEndExcluding = versionStr;
                case EQUAL -> exactVersions.add(versionStr);
                default -> LOGGER.warn(
                        "Encountered unexpected comparator {} in '{}' for {}; Skipping",
                        constraint.comparator(), vers, vulnId);
            }
        }

        for (final String exactVersion : exactVersions) {
            vsList.addAll(createVulnerableSoftware(
                    vulnId, affectedComponent, exactVersion, null, null, null, null));
        }

        if (versionStartIncluding != null || versionStartExcluding != null
                || versionEndIncluding != null || versionEndExcluding != null) {
            vsList.addAll(createVulnerableSoftware(vulnId, affectedComponent, null,
                    versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding));
        }

        if (vsList.isEmpty()) {
            LOGGER.warn("Unable to assemble a version range from '{}' for {}", vers, vulnId);
        }

        return vsList;
    }

    private static boolean isEffectivelyZero(Version version) {
        if (version == null) {
            return false;
        }
        return EFFECTIVELY_ZERO_PATTERN.matcher(version.toString()).matches();
    }

    private static List<VulnerableSoftware> createVulnerableSoftware(
            String vulnId,
            Component affectedComponent,
            String version,
            String versionStartIncluding,
            String versionStartExcluding,
            String versionEndIncluding,
            String versionEndExcluding) {
        final var vsList = new ArrayList<VulnerableSoftware>(2);

        if (affectedComponent.hasCpe()) {
            try {
                final Cpe cpe = CpeParser.parse(affectedComponent.getCpe());

                final var vs = new VulnerableSoftware();
                vs.setCpe22(cpe.toCpe22Uri());
                vs.setCpe23(affectedComponent.getCpe());
                vs.setPart(cpe.getPart().getAbbreviation());
                vs.setVendor(cpe.getVendor());
                vs.setProduct(cpe.getProduct());
                final String cpeVersion = cpe.getVersion();
                if (version != null && !version.equals(cpeVersion)) {
                    // NB: It doesn't make sense for CPE version and version to diverge
                    // (e.g. "*" vs "1.2.3"). CPEs either have an explicit version,
                    // or a wildcard with version ranges. This is a safeguard for a situation
                    // that *should* never happen, unless the upstream reports bad data.
                    LOGGER.warn("""
                                    BOV for {} reports CPE '{}' (version: '{}') alongside a diverging
                                    exact version '{}'; using the CPE's version.""",
                            vulnId, affectedComponent.getCpe(), cpeVersion, version);
                }
                vs.setVersion(cpeVersion);
                vs.setUpdate(cpe.getUpdate());
                vs.setEdition(cpe.getEdition());
                vs.setLanguage(cpe.getLanguage());
                vs.setSwEdition(cpe.getSwEdition());
                vs.setTargetSw(cpe.getTargetSw());
                vs.setTargetHw(cpe.getTargetHw());
                vs.setOther(cpe.getOther());
                vs.setVersionStartIncluding(versionStartIncluding);
                vs.setVersionStartExcluding(versionStartExcluding);
                vs.setVersionEndIncluding(versionEndIncluding);
                vs.setVersionEndExcluding(versionEndExcluding);
                vs.setVulnerable(true);

                vsList.add(vs);
            } catch (CpeParsingException e) {
                LOGGER.warn(
                        "Failed to parse CPE '{}' of {}; Skipping",
                        affectedComponent.getCpe(), vulnId, e);
            } catch (CpeEncodingException e) {
                LOGGER.warn(
                        "Failed to encode CPE '{}' of {}; Skipping",
                        affectedComponent.getCpe(), vulnId, e);
            }
        }

        if (affectedComponent.hasPurl()) {
            try {
                final PackageURL purl = new PackageURL(affectedComponent.getPurl());

                final var vs = new VulnerableSoftware();
                vs.setPurlType(purl.getType());
                vs.setPurlNamespace(purl.getNamespace());
                vs.setPurlName(purl.getName());
                vs.setPurlVersion(purl.getVersion());
                vs.setPurlQualifiers(PurlUtil.serializeQualifiers(purl));
                vs.setPurlSubpath(purl.getSubpath());
                vs.setPurl(purl.canonicalize());
                vs.setVersion(version);
                vs.setVersionStartIncluding(versionStartIncluding);
                vs.setVersionStartExcluding(versionStartExcluding);
                vs.setVersionEndIncluding(versionEndIncluding);
                vs.setVersionEndExcluding(versionEndExcluding);
                vs.setVulnerable(true);

                vsList.add(vs);
            } catch (MalformedPackageURLException e) {
                LOGGER.warn(
                        "Failed to parse PURL from '{}' for {}; Skipping",
                        affectedComponent.getPurl(), vulnId, e);
            }
        }

        return vsList;
    }

    public static Predicate<VulnerableSoftware> distinctIgnoringDatastoreIdentity() {
        final var seen = new HashSet<Integer>();
        return vs -> seen.add(vs.hashCodeWithoutDatastoreIdentity());
    }

}
