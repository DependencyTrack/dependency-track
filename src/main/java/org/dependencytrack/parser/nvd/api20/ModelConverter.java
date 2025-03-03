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
package org.dependencytrack.parser.nvd.api20;

import alpine.common.logging.Logger;
import io.github.jeremylong.openvulnerability.client.nvd.Config;
import io.github.jeremylong.openvulnerability.client.nvd.CpeMatch;
import io.github.jeremylong.openvulnerability.client.nvd.CveItem;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import io.github.jeremylong.openvulnerability.client.nvd.LangString;
import io.github.jeremylong.openvulnerability.client.nvd.Metrics;
import io.github.jeremylong.openvulnerability.client.nvd.Node;
import io.github.jeremylong.openvulnerability.client.nvd.Reference;
import io.github.jeremylong.openvulnerability.client.nvd.Weakness;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.util.VulnerabilityUtil;
import us.springett.cvss.Cvss;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.values.Part;

import java.math.BigDecimal;
import java.sql.Date;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Comparator.comparingInt;

/**
 * Utility class for conversions between the NVD's 2.0 API, and Dependency-Track's internal model.
 *
 * @since 4.10.0
 */
public final class ModelConverter {

    private static final Logger LOGGER = Logger.getLogger(ModelConverter.class);

    private ModelConverter() {
    }

    public static Vulnerability convert(final CveItem cveItem) {
        final var vuln = new Vulnerability();
        vuln.setVulnId(cveItem.getId());
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setDescription(convertDescriptions(cveItem.getDescriptions()));
        vuln.setReferences(convertReferences(cveItem.getReferences()));
        vuln.setCwes(convertWeaknesses(cveItem.getWeaknesses()));
        if (cveItem.getPublished() != null) {
            vuln.setPublished(Date.from(cveItem.getPublished().toInstant()));
        }
        if (cveItem.getLastModified() != null) {
            vuln.setUpdated(Date.from(cveItem.getLastModified().toInstant()));
        }
        convertCvssMetrics(cveItem.getMetrics(), vuln);
        return vuln;
    }

    private static String convertDescriptions(final List<LangString> descriptions) {
        if (descriptions == null || descriptions.isEmpty()) {
            return null;
        }

        return descriptions.stream()
                .filter(description -> "en".equalsIgnoreCase(description.getLang()))
                .map(LangString::getValue)
                .collect(Collectors.joining("\n\n"));
    }

    private static String convertReferences(final List<Reference> references) {
        if (references == null || references.isEmpty()) {
            return null;
        }

        return references.stream()
                .map(Reference::getUrl)
                .map(url -> "* [%s](%s)".formatted(url, url))
                .collect(Collectors.joining("\n"));
    }

    private static List<Integer> convertWeaknesses(final List<Weakness> weaknesses) {
        if (weaknesses == null) {
            return null;
        }

        return weaknesses.stream()
                .map(Weakness::getDescription)
                .flatMap(Collection::stream)
                .filter(description -> "en".equalsIgnoreCase(description.getLang()))
                .map(LangString::getValue)
                .map(CweResolver.getInstance()::parseCweString)
                .distinct()
                .toList();
    }

    private static void convertCvssMetrics(final Metrics metrics, final Vulnerability vuln) {
        if (metrics == null) {
            vuln.setSeverity(Severity.UNASSIGNED);
            return;
        }

        if (metrics.getCvssMetricV2() != null && !metrics.getCvssMetricV2().isEmpty()) {
            metrics.getCvssMetricV2().sort(comparingInt(metric -> metric.getType().ordinal()));

            for (final CvssV2 metric : metrics.getCvssMetricV2()) {
                final Cvss cvss = Cvss.fromVector(metric.getCvssData().getVectorString());
                vuln.setCvssV2Vector(cvss.getVector());
                vuln.setCvssV2BaseScore(BigDecimal.valueOf(metric.getCvssData().getBaseScore()));
                vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(metric.getExploitabilityScore()));
                vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(metric.getImpactScore()));
                break;
            }
        }

        if (metrics.getCvssMetricV31() != null && !metrics.getCvssMetricV31().isEmpty()) {
            metrics.getCvssMetricV31().sort(comparingInt(metric -> metric.getType().ordinal()));

            for (final CvssV3 metric : metrics.getCvssMetricV31()) {
                final Cvss cvss = Cvss.fromVector(metric.getCvssData().getVectorString());
                vuln.setCvssV3Vector(cvss.getVector());
                vuln.setCvssV3BaseScore(BigDecimal.valueOf(metric.getCvssData().getBaseScore()));
                vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(metric.getExploitabilityScore()));
                vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(metric.getImpactScore()));
                break;
            }
        } else if (metrics.getCvssMetricV30() != null && !metrics.getCvssMetricV30().isEmpty()) {
            metrics.getCvssMetricV30().sort(comparingInt(metric -> metric.getType().ordinal()));

            for (final CvssV3 metric : metrics.getCvssMetricV30()) {
                final Cvss cvss = Cvss.fromVector(metric.getCvssData().getVectorString());
                vuln.setCvssV3Vector(cvss.getVector());
                vuln.setCvssV3BaseScore(BigDecimal.valueOf(metric.getCvssData().getBaseScore()));
                vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(metric.getExploitabilityScore()));
                vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(metric.getImpactScore()));
                break;
            }
        }

        vuln.setSeverity(VulnerabilityUtil.getSeverity(
                vuln.getCvssV2BaseScore(),
                vuln.getCvssV3BaseScore(),
                vuln.getOwaspRRLikelihoodScore(),
                vuln.getOwaspRRTechnicalImpactScore(),
                vuln.getOwaspRRBusinessImpactScore()
        ));
    }

    public static List<VulnerableSoftware> convertConfigurations(final String cveId, final List<Config> configurations) {
        final List<CpeMatch> cpeMatches = extractCpeMatches(cveId, configurations);
        return cpeMatches.stream()
                .map(cpeMatch -> convertCpeMatch(cveId, cpeMatch))
                .filter(distinctIgnoringDatastoreIdentity())
                .collect(Collectors.toList());
    }

    public static Predicate<VulnerableSoftware> distinctIgnoringDatastoreIdentity() {
        final var seen = new HashSet<Integer>();
        return vs -> seen.add(vs.hashCodeWithoutDatastoreIdentity());
    }

    private static List<CpeMatch> extractCpeMatches(final String cveId, final List<Config> cveConfigs) {
        if (cveConfigs == null) {
            return Collections.emptyList();
        }

        final var cpeMatches = new ArrayList<CpeMatch>();
        for (final Config config : cveConfigs) {
            if (config.getNegate() != null && config.getNegate()) {
                // We can't compute negation.
                continue;
            }
            if (config.getNodes() == null || config.getNodes().isEmpty()) {
                continue;
            }

            config.getNodes().stream()
                    // We can't compute negation.
                    .filter(node -> node.getNegate() == null || !node.getNegate())
                    .filter(node -> node.getCpeMatch() != null)
                    .flatMap(node -> extractCpeMatchesFromNode(cveId, node))
                    // We currently have no interest in non-vulnerable versions.
                    .filter(cpeMatch -> cpeMatch.getVulnerable() == null || cpeMatch.getVulnerable())
                    .forEach(cpeMatches::add);
        }

        return cpeMatches;
    }

    private static Stream<CpeMatch> extractCpeMatchesFromNode(final String cveId, final Node node) {
        // Parse all CPEs in this node, and filter out those that cannot be parsed.
        // Because multiple `CpeMatch`es can refer to the same CPE, group them by CPE.
        final Map<Cpe, List<CpeMatch>> cpeMatchesByCpe = node.getCpeMatch().stream()
                .map(cpeMatch -> {
                    try {
                        return Pair.of(CpeParser.parse(cpeMatch.getCriteria()), cpeMatch);
                    } catch (CpeParsingException e) {
                        LOGGER.warn("Failed to parse CPE %s of %s; Skipping".formatted(cpeMatch.getCriteria(), cveId), e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.groupingBy(Pair::getLeft, Collectors.mapping(Pair::getRight, Collectors.toList())));

        // CVE configurations may consist of applications and operating systems. In the case of
        // configurations that contain both application and operating system parts, we do not
        // want both types of CPEs to be associated to the vulnerability as it will lead to
        // false positives on the operating system. https://nvd.nist.gov/vuln/detail/CVE-2015-0312
        // is a good example of this as it contains application CPEs describing various versions
        // of Adobe Flash player, but also contains CPEs for all versions of Windows, macOS, and
        // Linux.
        if (node.getOperator() == Node.Operator.AND) {
            // Re-group `CpeMatch`es by CPE part to determine which are against applications,
            // and which against operating systems. When matches are present for both of them,
            // only use the ones for applications.
            final Map<Part, List<CpeMatch>> cpeMatchesByPart = cpeMatchesByCpe.entrySet().stream()
                    .collect(Collectors.groupingBy(
                            entry -> entry.getKey().getPart(),
                            Collectors.flatMapping(entry -> entry.getValue().stream(), Collectors.toList())));
            if (!cpeMatchesByPart.getOrDefault(Part.APPLICATION, Collections.emptyList()).isEmpty()
                    && !cpeMatchesByPart.getOrDefault(Part.OPERATING_SYSTEM, Collections.emptyList()).isEmpty()) {
                return cpeMatchesByPart.get(Part.APPLICATION).stream();
            }
        }

        return cpeMatchesByCpe.values().stream()
                .flatMap(Collection::stream);
    }

    private static VulnerableSoftware convertCpeMatch(final String cveId, final CpeMatch cpeMatch) {
        try {
            final Cpe cpe = CpeParser.parse(cpeMatch.getCriteria());

            final var vs = new VulnerableSoftware();
            vs.setCpe22(cpe.toCpe22Uri());
            vs.setCpe23(cpeMatch.getCriteria());
            vs.setPart(cpe.getPart().getAbbreviation());
            vs.setVendor(cpe.getVendor());
            vs.setProduct(cpe.getProduct());
            vs.setVersion(cpe.getVersion());
            vs.setUpdate(cpe.getUpdate());
            vs.setEdition(cpe.getEdition());
            vs.setLanguage(cpe.getLanguage());
            vs.setSwEdition(cpe.getSwEdition());
            vs.setTargetSw(cpe.getTargetSw());
            vs.setTargetHw(cpe.getTargetHw());
            vs.setOther(cpe.getOther());
            vs.setVulnerable(true);

            vs.setVersionStartIncluding(cpeMatch.getVersionStartIncluding());
            vs.setVersionStartExcluding(cpeMatch.getVersionStartExcluding());
            vs.setVersionEndIncluding(cpeMatch.getVersionEndIncluding());
            vs.setVersionEndExcluding(cpeMatch.getVersionEndExcluding());

            return vs;
        } catch (CpeParsingException e) {
            LOGGER.warn("Failed to parse CPE %s of %s; Skipping".formatted(cpeMatch.getCriteria(), cveId));
            return null;
        } catch (CpeEncodingException e) {
            LOGGER.warn("Failed to encode CPE %s of %s; Skipping".formatted(cpeMatch.getCriteria(), cveId));
            return null;
        }
    }

}
