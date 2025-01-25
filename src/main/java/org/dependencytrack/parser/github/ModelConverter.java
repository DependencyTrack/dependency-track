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
package org.dependencytrack.parser.github;

import alpine.common.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import io.github.jeremylong.openvulnerability.client.ghsa.CVSS;
import io.github.jeremylong.openvulnerability.client.ghsa.CWE;
import io.github.jeremylong.openvulnerability.client.ghsa.CWEs;
import io.github.jeremylong.openvulnerability.client.ghsa.Package;
import io.github.jeremylong.openvulnerability.client.ghsa.Reference;
import io.github.jeremylong.openvulnerability.client.ghsa.SecurityAdvisory;
import io.github.jeremylong.openvulnerability.client.ghsa.Vulnerabilities;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.util.VulnerabilityUtil;
import us.springett.cvss.Cvss;
import us.springett.cvss.Score;

import java.math.BigDecimal;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import static com.github.packageurl.PackageURLBuilder.aPackageURL;

/**
 * @since 4.12.3
 */
public final class ModelConverter {

    private final Logger logger;

    public ModelConverter(final Logger logger) {
        this.logger = logger;
    }

    public Vulnerability convert(final SecurityAdvisory advisory) {
        if (advisory.getWithdrawnAt() != null) {
            // TODO: Mark the vulnerability as withdrawn instead,
            //  and handle it in the internal analyzer to:
            //    1. not create new findings for it
            //    2. auto-suppress existing findings
            logger.debug("Vulnerability was withdrawn at %s; Skipping".formatted(advisory.getWithdrawnAt()));
            return null;
        }

        final var vuln = new Vulnerability();
        vuln.setVulnId(advisory.getGhsaId());
        vuln.setSource(Vulnerability.Source.GITHUB);
        vuln.setDescription(advisory.getDescription());
        vuln.setTitle(advisory.getSummary());
        vuln.setPublished(convertDate(advisory.getPublishedAt()));
        vuln.setUpdated(convertDate(advisory.getUpdatedAt()));
        vuln.setReferences(convertReferences(advisory.getReferences()));
        vuln.setCwes(convertCwes(advisory.getCwes()));
        vuln.setSeverity(convertSeverity(advisory.getSeverity()));

        if (advisory.getCvssSeverities() != null) {
            final CVSS cvssv3 = advisory.getCvssSeverities().getCvssV3();
            if (cvssv3 != null) {
                final Cvss parsedCvssV3 = Cvss.fromVector(cvssv3.getVectorString());
                if (parsedCvssV3 != null) {
                    final Score calculatedScore = parsedCvssV3.calculateScore();
                    vuln.setCvssV3Vector(cvssv3.getVectorString());
                    vuln.setCvssV3BaseScore(BigDecimal.valueOf(calculatedScore.getBaseScore()));
                    vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(calculatedScore.getExploitabilitySubScore()));
                    vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(calculatedScore.getImpactSubScore()));
                }
            }

            // TODO: advisory.getCvssSeverities().getCvssV4()
            //  Requires CVSSv4 support in the DT data model.

            vuln.setSeverity(VulnerabilityUtil.getSeverity(
                    vuln.getSeverity(),
                    vuln.getCvssV2BaseScore(),
                    vuln.getCvssV3BaseScore(),
                    vuln.getOwaspRRLikelihoodScore(),
                    vuln.getOwaspRRTechnicalImpactScore(),
                    vuln.getOwaspRRBusinessImpactScore()));
        }

        if (advisory.getIdentifiers() != null && !advisory.getIdentifiers().isEmpty()) {
            vuln.setAliases(advisory.getIdentifiers().stream()
                    .filter(identifier -> "cve".equalsIgnoreCase(identifier.getType()))
                    .map(identifier -> {
                        final var alias = new VulnerabilityAlias();
                        alias.setGhsaId(advisory.getGhsaId());
                        alias.setCveId(identifier.getValue());
                        return alias;
                    })
                    .toList());
        }

        return vuln;
    }

    private Date convertDate(final ZonedDateTime zonedDateTime) {
        if (zonedDateTime == null) {
            return null;
        }

        return Date.from(zonedDateTime.toInstant());
    }

    private String convertReferences(final List<Reference> references) {
        if (references == null || references.isEmpty()) {
            return null;
        }

        final var stringJoiner = new StringJoiner("\n");
        for (final Reference reference : references) {
            stringJoiner.add("* [%s](%s)".formatted(reference.getUrl(), reference.getUrl()));
        }

        return stringJoiner.toString();
    }

    private List<Integer> convertCwes(final CWEs advisoryCwes) {
        if (advisoryCwes == null || advisoryCwes.getEdges() == null || advisoryCwes.getEdges().isEmpty()) {
            return null;
        }

        final var resolvedCweIds = new ArrayList<Integer>(advisoryCwes.getEdges().size());
        for (final CWE cwe : advisoryCwes.getEdges()) {
            final Cwe resolvedCwe = CweResolver.getInstance().lookup(cwe.getCweId());
            if (resolvedCwe != null) {
                resolvedCweIds.add(resolvedCwe.getCweId());
            }
        }

        return resolvedCweIds;
    }

    private Severity convertSeverity(
            final io.github.jeremylong.openvulnerability.client.ghsa.Severity ghsaSeverity) {
        if (ghsaSeverity == null) {
            return Severity.UNASSIGNED;
        }

        return switch (ghsaSeverity) {
            case LOW -> Severity.LOW;
            case MODERATE -> Severity.MEDIUM;
            case HIGH -> Severity.HIGH;
            case CRITICAL -> Severity.CRITICAL;
        };
    }

    public List<VulnerableSoftware> convert(final Vulnerabilities ghsaVulns) {
        if (ghsaVulns == null || ghsaVulns.getEdges() == null || ghsaVulns.getEdges().isEmpty()) {
            return null;
        }

        return ghsaVulns.getEdges().stream()
                .map(this::convert)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    private VulnerableSoftware convert(
            final io.github.jeremylong.openvulnerability.client.ghsa.Vulnerability ghsaVulnerability) {
        final PackageURL purl = convertToPurl(ghsaVulnerability.getPackage());
        if (purl == null) {
            return null;
        }

        final var vs = new VulnerableSoftware();
        vs.setPurlType(purl.getType());
        vs.setPurlNamespace(purl.getNamespace());
        vs.setPurlName(purl.getName());
        vs.setPurl(purl.toString());
        vs.setVulnerable(true);

        final String[] constraintExprs = ghsaVulnerability.getVulnerableVersionRange().split(",");
        for (int i = 0; i < constraintExprs.length; i++) {
            final String constraintExpr = constraintExprs[i].trim();

            if (constraintExpr.startsWith("<=")) {
                vs.setVersionEndIncluding(constraintExpr.substring(2).trim());
            } else if (constraintExpr.startsWith("<")) {
                vs.setVersionEndExcluding(constraintExpr.substring(1).trim());
            } else if (constraintExpr.startsWith(">=")) {
                vs.setVersionStartIncluding(constraintExpr.substring(2).trim());
            } else if (constraintExpr.startsWith(">")) {
                vs.setVersionStartExcluding(constraintExpr.substring(1).trim());
            } else if (constraintExpr.startsWith("=")) {
                vs.setVersion(constraintExpr.substring(1).trim());
            } else {
                logger.warn("Unrecognized constraint expression: " + constraintExpr);
            }
        }

        return vs;
    }

    private PackageURL convertToPurl(final Package pkg) {
        final String purlType = switch (pkg.getEcosystem().toLowerCase()) {
            case "composer" -> PackageURL.StandardTypes.COMPOSER;
            case "erlang" -> PackageURL.StandardTypes.HEX;
            case "go" -> PackageURL.StandardTypes.GOLANG;
            case "maven" -> PackageURL.StandardTypes.MAVEN;
            case "npm" -> PackageURL.StandardTypes.NPM;
            case "nuget" -> PackageURL.StandardTypes.NUGET;
            case "other" -> PackageURL.StandardTypes.GENERIC;
            case "pip" -> PackageURL.StandardTypes.PYPI;
            case "pub" -> "pub"; // https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#pub
            case "rubygems" -> PackageURL.StandardTypes.GEM;
            case "rust" -> PackageURL.StandardTypes.CARGO;
            case "swift" -> "swift"; // https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#swift
            default -> {
                // Not optimal, but still better than ignoring the package entirely.
                logger.warn("Unrecognized ecosystem %s; Assuming PURL type %s for %s".formatted(
                        pkg.getEcosystem(), PackageURL.StandardTypes.GENERIC, pkg));
                yield PackageURL.StandardTypes.GENERIC;
            }
        };

        final PackageURLBuilder purlBuilder = aPackageURL().withType(purlType);
        if (PackageURL.StandardTypes.MAVEN.equals(purlType) && pkg.getName().contains(":")) {
            final String[] nameParts = pkg.getName().split(":", 2);
            purlBuilder
                    .withNamespace(nameParts[0])
                    .withName(nameParts[1]);
        } else if ((PackageURL.StandardTypes.COMPOSER.equals(purlType)
                    || PackageURL.StandardTypes.GOLANG.equals(purlType)
                    || PackageURL.StandardTypes.NPM.equals(purlType)
                    || PackageURL.StandardTypes.GENERIC.equals(purlType))
                   && pkg.getName().contains("/")) {
            final String[] nameParts = pkg.getName().split("/");
            final String namespace = String.join("/", Arrays.copyOfRange(nameParts, 0, nameParts.length - 1));
            purlBuilder
                    .withNamespace(namespace)
                    .withName(nameParts[nameParts.length - 1]);
        } else {
            purlBuilder.withName(pkg.getName());
        }

        try {
            return purlBuilder.build();
        } catch (MalformedPackageURLException e) {
            logger.warn("Failed to assemble a valid PURL from " + pkg, e);
            return null;
        }
    }

}
