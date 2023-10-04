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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.util;

import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;

import java.math.BigDecimal;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Set;

public final class VulnerabilityUtil {

    public static final SecureRandom DEFAULT_NUMBER_GENERATOR = new SecureRandom();
    public static final char[] DEFAULT_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz".toCharArray();
    public static final Map<Severity, Map<Severity, Severity>> OWASP_RR_LIKELIHOOD_TO_IMPACT_SEVERITY_MATRIX = Map.of(
      Severity.LOW, Map.of(
        Severity.LOW, Severity.INFO,
        Severity.MEDIUM, Severity.LOW,
        Severity.HIGH, Severity.MEDIUM,
        Severity.UNASSIGNED, Severity.UNASSIGNED
      ),
      Severity.MEDIUM, Map.of(
        Severity.LOW, Severity.LOW,
        Severity.MEDIUM, Severity.MEDIUM,
        Severity.HIGH, Severity.HIGH,
        Severity.UNASSIGNED, Severity.UNASSIGNED
      ),
      Severity.HIGH, Map.of(
        Severity.LOW, Severity.MEDIUM,
        Severity.MEDIUM, Severity.HIGH,
        Severity.HIGH, Severity.CRITICAL,
        Severity.UNASSIGNED, Severity.UNASSIGNED
      ),
      Severity.UNASSIGNED, Map.of(
        Severity.LOW, Severity.UNASSIGNED,
        Severity.MEDIUM, Severity.UNASSIGNED,
        Severity.HIGH, Severity.UNASSIGNED,
        Severity.UNASSIGNED, Severity.UNASSIGNED
      )
    );

    private VulnerabilityUtil() { }

    /**
     * Returns the value of the severity field (if specified), otherwise, will
     * return the severity based on the numerical CVSS or OWASP RR score.
     *
     * This method properly accounts for vulnerabilities that may have a subset or all of (CVSSv2, CVSSv3, OWASP RR)
     * score. The highest severity is returned.
     * @return the severity of the vulnerability
     * @since 3.2.1
     */
    public static Severity getSeverity(final Object severity, final BigDecimal cvssV2BaseScore, final BigDecimal cvssV3BaseScore, final BigDecimal owaspRRLikelihoodScore, final BigDecimal owaspRRTechnicalImpactScore, final BigDecimal owaspRRBusinessImpactScore) {
        if (severity instanceof String) {
            final String s = (String)severity;
            if (s.equalsIgnoreCase(Severity.CRITICAL.name())) {
                return Severity.CRITICAL;
            } else if (s.equalsIgnoreCase(Severity.HIGH.name())) {
                return Severity.HIGH;
            } else if (s.equalsIgnoreCase(Severity.MEDIUM.name())) {
                return Severity.MEDIUM;
            } else if (s.equalsIgnoreCase(Severity.LOW.name())) {
                return Severity.LOW;
            } else if (s.equalsIgnoreCase(Severity.INFO.name())) {
                return Severity.INFO;
            }
        } else if (severity instanceof Severity) {
            return (Severity)severity;
        } else {
            return getSeverity(cvssV2BaseScore, cvssV3BaseScore, owaspRRLikelihoodScore, owaspRRTechnicalImpactScore, owaspRRBusinessImpactScore);
        }
        return Severity.UNASSIGNED;
    }

    /**
     * Returns the severity based on the numerical CVSS and/or OWASP RR score.
     *
     * This method properly accounts for vulnerabilities that may have a subset or all of (CVSSv2, CVSSv3, OWASP RR) score. The highest severity is returned.
     *
     * @return the severity of the vulnerability
     * @since 3.1.0
     */
    public static Severity getSeverity(final BigDecimal cvssV2BaseScore, final BigDecimal cvssV3BaseScore, final BigDecimal owaspRRLikelihoodScore, final BigDecimal owaspRRTechnicalImpactScore, final BigDecimal owaspRRBusinessImpactScore) {
        Severity severity = Severity.UNASSIGNED;
        Severity cvssSeverity = null, owaspRRSeverity = null;
        if (cvssV3BaseScore != null) {
            cvssSeverity = normalizedCvssV3Score(cvssV3BaseScore.doubleValue());
        } else if (cvssV2BaseScore != null) {
            cvssSeverity = normalizedCvssV2Score(cvssV2BaseScore.doubleValue());
        }

        if (owaspRRLikelihoodScore != null && owaspRRTechnicalImpactScore != null && owaspRRBusinessImpactScore != null) {
            owaspRRSeverity = normalizedOwaspRRScore(owaspRRLikelihoodScore.doubleValue(), owaspRRTechnicalImpactScore.doubleValue(), owaspRRBusinessImpactScore.doubleValue());
        }

        if (owaspRRSeverity != null && cvssSeverity != null) {
            severity = owaspRRSeverity.getLevel() > cvssSeverity.getLevel() ? owaspRRSeverity : cvssSeverity;
        } else if (owaspRRSeverity != null) {
            severity = owaspRRSeverity;
        } else if (cvssSeverity != null) {
            severity = cvssSeverity;
        }

        return severity;
    }

    /**
     * Returns the severity based on the numerical CVSS score.
     * @return the severity of the vulnerability
     * @since 3.1.0
     */
    public static Severity normalizedCvssV2Score(final double score) {
        if (score >= 7) {
            return Severity.HIGH;
        } else if (score >= 4) {
            return Severity.MEDIUM;
        } else if (score > 0) {
            return Severity.LOW;
        } else {
            return Severity.UNASSIGNED;
        }
    }

    /**
     * Returns the severity based on the numerical CVSS score.
     * @return the severity of the vulnerability
     * @since 3.1.0
     */
    public static Severity normalizedCvssV3Score(final double score) {
        if (score >= 9) {
            return Severity.CRITICAL;
        } else if (score >= 7) {
            return Severity.HIGH;
        } else if (score >= 4) {
            return Severity.MEDIUM;
        } else if (score > 0) {
            return Severity.LOW;
        } else {
            return Severity.UNASSIGNED;
        }
    }

    public static Severity normalizedOwaspRRScore(final double likelihoodScore, final double technicalImpactScore, final double businessImpactScore) {
        double impactScore = Math.max(technicalImpactScore, businessImpactScore);
        Severity likelihoodSeverity = normalizedOwaspRRScore(likelihoodScore);
        Severity impactSeverity = normalizedOwaspRRScore(impactScore);
        return OWASP_RR_LIKELIHOOD_TO_IMPACT_SEVERITY_MATRIX.get(likelihoodSeverity).get(impactSeverity);
    }

    public static Severity normalizedOwaspRRScore(final double score) {
        if (score >= 6) {
            return Severity.HIGH;
        } else if (score >= 3) {
            return Severity.MEDIUM;
        } else if (score > 0) {
            return Severity.LOW;
        } else {
            return Severity.UNASSIGNED;
        }
    }

    /**
     * Generates a random ODT vulnerability identifier, based on the NanoId library
     *
     * @return A randomly generated NanoId String.
     */
    public static String randomInternalId() {
        final Random random = DEFAULT_NUMBER_GENERATOR;
        final char[] alphabet = DEFAULT_ALPHABET;
        final int size = 12;

        final int mask = (2 << (int) Math.floor(Math.log(alphabet.length - 1) / Math.log(2))) - 1;
        final int step = (int) Math.ceil(1.6 * mask * size / alphabet.length);

        final StringBuilder idBuilder = new StringBuilder();
        while (true) {
            final byte[] bytes = new byte[step];
            random.nextBytes(bytes);
            for (int i = 0; i < step; i++) {
                final int alphabetIndex = bytes[i] & mask;
                if (alphabetIndex < alphabet.length) {
                    idBuilder.append(alphabet[alphabetIndex]);
                    if (idBuilder.length() == size) {
                        return idBuilder.toString().replaceFirst("(\\p{Alnum}{4})(\\p{Alnum}{4})(\\p{Alnum}+)", "INT-$1-$2-$3");
                    }
                }
            }
        }
    }

    /**
     * Computes a {@link Set} of unique source-to-vulnId combinations that alias the given {@link Vulnerability}.
     * The result does not include the source and ID of the {@link Vulnerability} itself.
     * <p>
     * The result can not be a {@link Map}, because a {@link Vulnerability} may be aliased by
     * multiple vulnerabilities from the same source. Using a {@link Map} would make such constellations impossible.
     *
     * @param vulnerability The {@link Vulnerability} to compute unique aliases for
     * @return Unique aliases, or {@code null} when either the vulnerability itself or its aliases are {@code null}
     */
    public static Set<Map.Entry<Vulnerability.Source, String>> getUniqueAliases(final Vulnerability vulnerability) {
        if (vulnerability == null || vulnerability.getAliases() == null) {
            return Collections.emptySet();
        }

        final Set<Map.Entry<Vulnerability.Source, String>> uniqueAliases = new HashSet<>();
        for (final VulnerabilityAlias alias : vulnerability.getAliases()) {
            alias.getAllBySource().entrySet().stream()
                    .filter(vulnIdBySource ->
                            !vulnIdBySource.getKey().name().equals(vulnerability.getSource())
                                || !vulnIdBySource.getValue().equals(vulnerability.getVulnId()))
                    .forEach(uniqueAliases::add);
        }

        return uniqueAliases;
    }

}
