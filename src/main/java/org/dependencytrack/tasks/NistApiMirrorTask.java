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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.model.ConfigProperty;
import alpine.security.crypto.DataEncryption;
import io.github.jeremylong.openvulnerability.client.nvd.Config;
import io.github.jeremylong.openvulnerability.client.nvd.CpeMatch;
import io.github.jeremylong.openvulnerability.client.nvd.CveItem;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import io.github.jeremylong.openvulnerability.client.nvd.LangString;
import io.github.jeremylong.openvulnerability.client.nvd.Node;
import io.github.jeremylong.openvulnerability.client.nvd.NvdCveClient;
import io.github.jeremylong.openvulnerability.client.nvd.NvdCveClientBuilder;
import io.github.jeremylong.openvulnerability.client.nvd.Weakness;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.IndexEvent.Action;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.Vulnerability.Source;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.persistence.QueryManager;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.values.Part;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.sql.Date;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.github.jeremylong.openvulnerability.client.nvd.NvdCveClientBuilder.aNvdCveApi;
import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_KEY;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_URL;
import static org.dependencytrack.util.PersistenceUtil.applyIfChanged;
import static org.dependencytrack.util.PersistenceUtil.applyIfNonNullAndChanged;

/**
 * A {@link Subscriber} that mirrors the content of the NVD through the NVD API 2.0.
 *
 * @since 4.10.0
 */
public class NistApiMirrorTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(NistApiMirrorTask.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
        if (!(e instanceof NistMirrorEvent)) {
            return;
        }

        final String apiUrl, apiKey;
        final long lastModifiedEpochSeconds;
        try (final var qm = new QueryManager()) {
            final ConfigProperty apiUrlProperty = qm.getConfigProperty(
                    VULNERABILITY_SOURCE_NVD_API_URL.getGroupName(),
                    VULNERABILITY_SOURCE_NVD_API_URL.getPropertyName()
            );
            final ConfigProperty apiKeyProperty = qm.getConfigProperty(
                    VULNERABILITY_SOURCE_NVD_API_KEY.getGroupName(),
                    VULNERABILITY_SOURCE_NVD_API_KEY.getPropertyName()
            );
            final ConfigProperty lastModifiedProperty = qm.getConfigProperty(
                    VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS.getGroupName(),
                    VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS.getPropertyName()
            );

            apiUrl = Optional.ofNullable(apiUrlProperty)
                    .map(ConfigProperty::getPropertyValue)
                    .map(StringUtils::trimToNull)
                    .orElseThrow(() -> new IllegalStateException("No API URL configured"));
            apiKey = Optional.ofNullable(apiKeyProperty)
                    .map(ConfigProperty::getPropertyValue)
                    .map(StringUtils::trimToNull)
                    .map(encryptedApiKey -> {
                        try {
                            return DataEncryption.decryptAsString(encryptedApiKey);
                        } catch (Exception ex) {
                            LOGGER.warn("Failed to decrypt API key; Continuing without authentication", ex);
                            return null;
                        }
                    })
                    .orElse(null);
            lastModifiedEpochSeconds = Optional.ofNullable(lastModifiedProperty)
                    .map(ConfigProperty::getPropertyValue)
                    .map(StringUtils::trimToNull)
                    .filter(StringUtils::isNumeric)
                    .map(Long::parseLong)
                    .orElse(0L);
        }

        final long startTimeNs = System.nanoTime();
        try (final NvdCveClient client = createApiClient(apiUrl, apiKey, lastModifiedEpochSeconds)) {
            while (client.hasNext()) {
                for (final DefCveItem defCveItem : client.next()) {
                    if (defCveItem.getCve() != null) {
                        try (final var qm = new QueryManager().withL2CacheDisabled()) {
                            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");
                            processCve(qm, defCveItem.getCve());
                        }
                    }
                }
            }

            if (updateLastModified(client.getLastUpdated())) {
                Event.dispatch(new IndexEvent(Action.COMMIT, Vulnerability.class));
            }
        } catch (Exception ex) {
            LOGGER.error("An unexpected error occurred while mirroring the contents of the National Vulnerability Database", ex);
        } finally {
            LOGGER.info("Mirroring completed in %s".formatted(Duration.ofNanos(System.nanoTime() - startTimeNs)));
        }
    }

    private static void processCve(final QueryManager qm, final CveItem cveItem) {
        final Vulnerability vuln = convertVulnerability(cveItem);
        final List<VulnerableSoftware> vsList = extractCpeMatches(cveItem.getId(), cveItem.getConfigurations())
                .map(cpeMatch -> convertCpeMatch(cveItem.getId(), cpeMatch))
                .filter(Objects::nonNull)
                .toList();

        final Vulnerability persistentVuln = synchronizeVulnerability(qm, vuln);
        synchronizeVulnerableSoftware(qm, persistentVuln, vsList);
    }

    private static Vulnerability synchronizeVulnerability(final QueryManager qm, final Vulnerability vuln) {
        final Pair<Vulnerability, IndexEvent> vulnIndexEventPair = qm.runInTransaction(() -> {
            final PersistenceManager pm = qm.getPersistenceManager();
            final Query<Vulnerability> query = pm.newQuery(Vulnerability.class);
            query.setFilter("source == :source && vulnId == :vulnId");
            query.setNamedParameters(Map.of(
                    "source", Source.NVD.name(),
                    "vulnId", vuln.getVulnId()
            ));
            Vulnerability persistentVuln;
            try {
                persistentVuln = query.executeUnique();
            } finally {
                query.closeAll();
            }

            if (persistentVuln == null) {
                persistentVuln = pm.makePersistent(vuln);
                return Pair.of(persistentVuln, new IndexEvent(Action.CREATE, persistentVuln));
            } else {
                var updated = false;
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getTitle, persistentVuln::setTitle);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getSubTitle, persistentVuln::setSubTitle);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getDescription, persistentVuln::setDescription);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getDetail, persistentVuln::setDetail);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getRecommendation, persistentVuln::setRecommendation);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getReferences, persistentVuln::setReferences);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getCredits, persistentVuln::setCredits);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getCreated, persistentVuln::setCreated);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getPublished, persistentVuln::setPublished);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getUpdated, persistentVuln::setUpdated);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getCwes, persistentVuln::setCwes);
                // Calling setSeverity nulls all CVSS and OWASP RR fields. getSeverity calculates the severity on-the-fly,
                // and will return UNASSIGNED even when no severity is set explicitly. Thus, calling setSeverity
                // must happen before CVSS and OWASP RR fields are set, to avoid null-ing them again.
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getSeverity, persistentVuln::setSeverity);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getCvssV2BaseScore, persistentVuln::setCvssV2BaseScore);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getCvssV2ImpactSubScore, persistentVuln::setCvssV2ImpactSubScore);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getCvssV2ExploitabilitySubScore, persistentVuln::setCvssV2ExploitabilitySubScore);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getCvssV2Vector, persistentVuln::setCvssV2Vector);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getCvssV3BaseScore, persistentVuln::setCvssV3BaseScore);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getCvssV3ImpactSubScore, persistentVuln::setCvssV3ImpactSubScore);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getCvssV3ExploitabilitySubScore, persistentVuln::setCvssV3ExploitabilitySubScore);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getCvssV3Vector, persistentVuln::setCvssV3Vector);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getOwaspRRLikelihoodScore, persistentVuln::setOwaspRRLikelihoodScore);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getOwaspRRTechnicalImpactScore, persistentVuln::setOwaspRRTechnicalImpactScore);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getOwaspRRBusinessImpactScore, persistentVuln::setOwaspRRBusinessImpactScore);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getOwaspRRVector, persistentVuln::setOwaspRRVector);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getVulnerableVersions, persistentVuln::setVulnerableVersions);
                updated |= applyIfChanged(persistentVuln, vuln, Vulnerability::getPatchedVersions, persistentVuln::setPatchedVersions);
                // EPSS is an additional enrichment that no source currently provides natively. We don't want EPSS scores of CVEs to be purged.
                updated |= applyIfNonNullAndChanged(persistentVuln, vuln, Vulnerability::getEpssScore, persistentVuln::setEpssScore);
                updated |= applyIfNonNullAndChanged(persistentVuln, vuln, Vulnerability::getEpssPercentile, persistentVuln::setEpssPercentile);

                if (updated) {
                    LOGGER.debug("%s has changed".formatted(vuln.getVulnId()));
                    return Pair.of(persistentVuln, new IndexEvent(Action.UPDATE, persistentVuln));
                }

                LOGGER.debug("%s has not changed".formatted(vuln.getVulnId()));
                return Pair.of(persistentVuln, null);
            }
        });

        final IndexEvent indexEvent = vulnIndexEventPair.getRight();
        final Vulnerability persistentVuln = vulnIndexEventPair.getLeft();

        if (indexEvent != null) {
            Event.dispatch(indexEvent);
        }

        return persistentVuln;
    }

    private static void synchronizeVulnerableSoftware(final QueryManager qm, final Vulnerability persistentVuln,
                                                      final List<VulnerableSoftware> vsList) {
        qm.runInTransaction(() -> {
            final PersistenceManager pm = qm.getPersistenceManager();
            final List<VulnerableSoftware> persistentVsListOld = List.copyOf(pm.detachCopyAll(qm.getVulnerableSoftwareByVulnId(Source.NVD.name(), persistentVuln.getVulnId())));
            final List<VulnerableSoftware> persistentVsList = (List<VulnerableSoftware>) pm.makePersistentAll(vsList);
            qm.updateAffectedVersionAttributions(persistentVuln, persistentVsList, Source.NVD);
            final List<VulnerableSoftware> reconciledPersistentVsList =
                    qm.reconcileVulnerableSoftware(persistentVuln, persistentVsList, persistentVsListOld, Source.NVD);
            persistentVuln.setVulnerableSoftware(reconciledPersistentVsList);
        });
    }

    private static Vulnerability convertVulnerability(final CveItem cveItem) {
        final var vuln = new Vulnerability();
        vuln.setVulnId(cveItem.getId());
        vuln.setSource(Source.NVD);
        if (cveItem.getDescriptions() != null) {
            vuln.setDescription(cveItem.getDescriptions().stream()
                    .filter(description -> "en".equalsIgnoreCase(description.getLang()))
                    .map(LangString::getValue)
                    .collect(Collectors.joining("\n\n")));
        }
        vuln.setCwes(convertWeaknesses(cveItem.getWeaknesses()));
        if (cveItem.getPublished() != null) {
            vuln.setPublished(Date.from(cveItem.getPublished().toInstant()));
        }
        if (cveItem.getLastModified() != null) {
            vuln.setUpdated(Date.from(cveItem.getLastModified().toInstant()));
        }

        return vuln;
    }

    private static List<Integer> convertWeaknesses(final List<Weakness> weaknesses) {
        if (weaknesses == null) {
            return Collections.emptyList();
        }

        return weaknesses.stream()
                .map(Weakness::getDescription)
                .filter(Objects::nonNull)
                .flatMap(Collection::stream)
                .filter(description -> "en".equalsIgnoreCase(description.getLang()))
                .map(LangString::getValue)
                .map(CweResolver.getInstance()::parseCweString)
                .toList();
    }

    private static Stream<CpeMatch> extractCpeMatches(final String cveId, final List<Config> cveConfigs) {
        if (cveConfigs == null) {
            return Stream.empty();
        }

        return cveConfigs.stream()
                // We can't compute negation.
                .filter(config -> config.getNegate() == null || !config.getNegate())
                .map(Config::getNodes)
                .flatMap(Collection::stream)
                // We can't compute negation.
                .filter(node -> node.getNegate() == null || !node.getNegate())
                .filter(node -> node.getCpeMatch() != null)
                .flatMap(node -> extractCpeMatchesFromNode(cveId, node))
                // We currently have no interest in non-vulnerable versions.
                .filter(cpeMatch -> cpeMatch.getVulnerable() == null || cpeMatch.getVulnerable());
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
        if (node.getOperator() != Node.Operator.AND) {
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
            vs.setCpe23(cpe.toCpe23FS());
            vs.setPart(cpe.getPart().getAbbreviation());
            vs.setVendor(cpe.getVendor());
            vs.setProduct(cpe.getProduct());
            vs.setVersion(cpe.getVersion());
            vs.setUpdate(cpe.getUpdate());

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

    private static NvdCveClient createApiClient(final String apiUrl, final String apiKey, final long lastModifiedEpochSeconds) {
        final NvdCveClientBuilder clientBuilder = aNvdCveApi().withEndpoint(apiUrl);
        if (apiKey != null) {
            clientBuilder.withApiKey(apiKey);
        } else {
            LOGGER.warn("No API key configured; Aggressive rate limiting to be expected");
        }
        if (lastModifiedEpochSeconds > 0) {
            final var start = ZonedDateTime.ofInstant(Instant.ofEpochSecond(lastModifiedEpochSeconds), ZoneOffset.UTC);
            clientBuilder.withLastModifiedFilter(start, start.minusDays(-120));
            LOGGER.info("Mirroring CVEs that were modified since %s".formatted(start));
        } else {
            LOGGER.info("Mirroring CVEs that were modified since %s"
                    .formatted(ZonedDateTime.ofInstant(Instant.EPOCH, ZoneOffset.UTC)));
        }

        return clientBuilder.build();
    }

    private static boolean updateLastModified(final ZonedDateTime lastModifiedDateTime) {
        if (lastModifiedDateTime == null) {
            // Nothing has changed.
            return false;
        }

        try (final var qm = new QueryManager().withL2CacheDisabled()) {
            qm.runInTransaction(() -> {
                final ConfigProperty property = qm.getConfigProperty(
                        VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS.getGroupName(),
                        VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS.getPropertyName()
                );

                property.setPropertyValue(String.valueOf(lastModifiedDateTime.toEpochSecond()));
            });
        }

        return true;
    }

}
