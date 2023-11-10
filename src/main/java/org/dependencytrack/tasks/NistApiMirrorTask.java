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
import org.datanucleus.flush.FlushMode;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.IndexEvent.Action;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.model.AffectedVersionAttribution;
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.github.jeremylong.openvulnerability.client.nvd.NvdCveClientBuilder.aNvdCveApi;
import static org.datanucleus.PropertyNames.PROPERTY_FLUSH_MODE;
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

    public NistApiMirrorTask() {
    }

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
                            // TODO: Skipping decryption for easier local testing. Add this back in.
                            // DataEncryption.decryptAsString(encryptedApiKey);
                            return encryptedApiKey;
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
                .filter(distinctIgnoringDatastoreIdentity())
                .collect(Collectors.toList());

        final Vulnerability persistentVuln = synchronizeVulnerability(qm, vuln);
        synchronizeVulnerableSoftware(qm, persistentVuln, vsList);
    }

    private static Vulnerability synchronizeVulnerability(final QueryManager qm, final Vulnerability vuln) {
        final Pair<Vulnerability, IndexEvent> vulnIndexEventPair = qm.runInTransaction(trx -> {
            trx.setSerializeRead(true); // SELECT ... FOR UPDATE

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

    private static void synchronizeVulnerableSoftware(final QueryManager qm, final Vulnerability persistentVuln, final List<VulnerableSoftware> vsList) {
        // Delay flushes to the datastore until commit.
        qm.getPersistenceManager().setProperty(PROPERTY_FLUSH_MODE, FlushMode.MANUAL.name());

        qm.runInTransaction(tx -> {
            tx.setSerializeRead(false);

            // Get all `VulnerableSoftware`s that are currently associated with the `Vulnerability`.
            // Also fetch attributions as we will need to update those.
            final Query<VulnerableSoftware> oldVsListQuery = qm.getPersistenceManager().newQuery(VulnerableSoftware.class);
            oldVsListQuery.getFetchPlan().addGroup(VulnerableSoftware.FetchGroups.ATTRIBUTIONS);
            oldVsListQuery.setFilter("vulnerabilities.contains(:vuln)");
            oldVsListQuery.setParameters(persistentVuln);
            final List<VulnerableSoftware> oldVsList;
            try {
                oldVsList = List.copyOf(oldVsListQuery.executeList());
            } finally {
                oldVsListQuery.closeAll();
            }
            LOGGER.debug("%s: Existing VS: %d".formatted(persistentVuln.getVulnId(), oldVsList.size()));

            // Based on the lists of currently reported, and previously reported `VulnerableSoftware`s,
            // divide the previously reported ones into lists of items to keep, and items to remove.
            // Remaining items in vsList are entirely new.
            final var vsListToRemove = new ArrayList<VulnerableSoftware>();
            final var vsListToKeep = new ArrayList<VulnerableSoftware>();
            for (final VulnerableSoftware oldVs : oldVsList) {
                if (vsList.removeIf(isEqualToIgnoringDatastoreIdentity(oldVs))) {
                    vsListToKeep.add(oldVs);
                } else {
                    final List<AffectedVersionAttribution> attributions = oldVs.getAffectedVersionAttributions();
                    if (attributions == null) {
                        // DT versions prior to 4.7.0 did not record attributions.
                        // Drop the VulnerableSoftware for now. If it was previously
                        // reported by another source, it will be recorded and attributed
                        // whenever that source is mirrored again.
                        vsListToRemove.add(oldVs);
                        continue;
                    }

                    final boolean previouslyReportedBySource = attributions.stream()
                            .anyMatch(attr -> attr.getSource() == Source.NVD);
                    final boolean previouslyReportedByOthers = attributions.stream()
                            .anyMatch(attr -> attr.getSource() != Source.NVD);

                    if (previouslyReportedByOthers) {
                        // Reported by another source, keep it.
                        vsListToKeep.add(oldVs);
                    } else if (previouslyReportedBySource) {
                        // Not reported anymore, remove attribution.
                        vsListToRemove.add(oldVs);
                    } else {
                        // Should never happen, but better safe than sorry.
                        vsListToRemove.add(oldVs);
                    }
                }
            }
            LOGGER.debug("%s: vsListToKeep: %d".formatted(persistentVuln.getVulnId(), vsListToKeep.size()));
            LOGGER.debug("%s: vsListToRemove: %d".formatted(persistentVuln.getVulnId(), vsListToRemove.size()));

            // Remove attributions from `VulnerableSoftware`s that are no longer reported.
            if (!vsListToRemove.isEmpty()) {
                final Query<AffectedVersionAttribution> deleteAttributionQuery = qm.getPersistenceManager().newQuery(AffectedVersionAttribution.class);
                deleteAttributionQuery.setFilter(":vsListToRemove.contains(vulnerableSoftware) && source == :source");
                deleteAttributionQuery.setNamedParameters(Map.of(
                        "vsListToRemove", vsListToRemove,
                        "source", Source.NVD
                ));
                try {
                    deleteAttributionQuery.deletePersistentAll();
                } finally {
                    deleteAttributionQuery.closeAll();
                }
            }

            final var attributionDate = new java.util.Date();

            // For `VulnerableSoftware`s that existed before, update the lastSeen timestamp.
            for (final VulnerableSoftware oldVs : vsListToKeep) {
                oldVs.getAffectedVersionAttributions().stream()
                        .filter(attribution -> attribution.getSource() == Source.NVD)
                        .findAny()
                        .ifPresent(attribution -> attribution.setLastSeen(attributionDate));
            }

            // For `VulnerableSoftware`s that are newly reported for this `Vulnerability`, check if any matching
            // records exist in the database that are currently associated with other `Vulnerability`s.
            for (final VulnerableSoftware vs : vsList) {
                final Query<VulnerableSoftware> query = qm.getPersistenceManager().newQuery(VulnerableSoftware.class);
                query.getFetchPlan().addGroup(VulnerableSoftware.FetchGroups.ATTRIBUTIONS);
                final var queryFilter = new StringBuilder();
                final var queryParams = new HashMap<String, Object>();
                final BiConsumer<String, Object> foo = (name, value) -> {
                    if (!queryFilter.isEmpty()) {
                        queryFilter.append(" && ");
                    }
                    if (value == null) {
                        queryFilter.append("%s == null".formatted(name));
                    } else {
                        queryFilter.append("%s == :%s".formatted(name, name));
                        queryParams.put(name, value);
                    }
                };
                foo.accept("cpe23", vs.getCpe23());
                foo.accept("versionEndExcluding", vs.getVersionEndExcluding());
                foo.accept("versionEndIncluding", vs.getVersionEndIncluding());
                foo.accept("versionStartExcluding", vs.getVersionStartExcluding());
                foo.accept("versionStartIncluding", vs.getVersionStartIncluding());
                query.setFilter(queryFilter.toString());
                query.setNamedParameters(queryParams);
                final VulnerableSoftware existingVs;
                try {
                    existingVs = query.executeUnique();
                } finally {
                    query.closeAll();
                }
                if (existingVs != null) {
                    final boolean hasAttribution = existingVs.getAffectedVersionAttributions().stream()
                            .anyMatch(attribution -> attribution.getSource() == Source.NVD);
                    if (!hasAttribution) {
                        LOGGER.info("%s: Adding attribution".formatted(persistentVuln.getVulnId()));
                        final var attribution = new AffectedVersionAttribution();
                        attribution.setSource(Source.NVD);
                        attribution.setVulnerability(persistentVuln);
                        attribution.setVulnerableSoftware(existingVs);
                        attribution.setFirstSeen(attributionDate);
                        attribution.setLastSeen(attributionDate);
                        qm.getPersistenceManager().makePersistent(attribution);
                        existingVs.getAffectedVersionAttributions().add(attribution);
                    }
                    vsListToKeep.add(existingVs);
                } else {
                    LOGGER.debug("%s: Creating new VS".formatted(persistentVuln.getVulnId()));
                    final VulnerableSoftware persistentVs = qm.getPersistenceManager().makePersistent(vs);

                    final var attribution = new AffectedVersionAttribution();
                    attribution.setSource(Source.NVD);
                    attribution.setVulnerability(persistentVuln);
                    attribution.setVulnerableSoftware(persistentVs);
                    attribution.setFirstSeen(attributionDate);
                    attribution.setLastSeen(attributionDate);
                    qm.getPersistenceManager().makePersistent(attribution);
                    vsListToKeep.add(persistentVs);
                }
            }

            LOGGER.debug("%s: Final vsList: %d".formatted(persistentVuln.getVulnId(), vsListToKeep.size()));
            persistentVuln.setVulnerableSoftware(vsListToKeep);
        });
    }

    private static Predicate<VulnerableSoftware> isEqualToIgnoringDatastoreIdentity(final VulnerableSoftware vsOld) {
        return vs -> Objects.equals(vsOld.getPurl(), vs.getPurl())
                && Objects.equals(vsOld.getPurlType(), vs.getPurlType())
                && Objects.equals(vsOld.getPurlNamespace(), vs.getPurlNamespace())
                && Objects.equals(vsOld.getPurlName(), vs.getPurlName())
                && Objects.equals(vsOld.getPurlVersion(), vs.getPurlVersion())
                && Objects.equals(vsOld.getPurlQualifiers(), vs.getPurlQualifiers())
                && Objects.equals(vsOld.getPurlSubpath(), vs.getPurlSubpath())
                && Objects.equals(vsOld.getCpe22(), vs.getCpe22())
                && Objects.equals(vsOld.getCpe23(), vs.getCpe23())
                && Objects.equals(vsOld.getPart(), vs.getPart())
                && Objects.equals(vsOld.getVendor(), vs.getVendor())
                && Objects.equals(vsOld.getProduct(), vs.getProduct())
                && Objects.equals(vsOld.getVersion(), vs.getVersion())
                && Objects.equals(vsOld.getUpdate(), vs.getUpdate())
                && Objects.equals(vsOld.getEdition(), vs.getEdition())
                && Objects.equals(vsOld.getLanguage(), vs.getLanguage())
                && Objects.equals(vsOld.getSwEdition(), vs.getSwEdition())
                && Objects.equals(vsOld.getTargetSw(), vs.getTargetSw())
                && Objects.equals(vsOld.getTargetHw(), vs.getTargetHw())
                && Objects.equals(vsOld.getOther(), vs.getOther())
                && Objects.equals(vsOld.getVersionEndExcluding(), vs.getVersionEndExcluding())
                && Objects.equals(vsOld.getVersionEndIncluding(), vs.getVersionEndIncluding())
                && Objects.equals(vsOld.getVersionStartExcluding(), vs.getVersionStartExcluding())
                && Objects.equals(vsOld.getVersionStartIncluding(), vs.getVersionStartIncluding())
                && Objects.equals(vsOld.isVulnerable(), vs.isVulnerable());
    }

    private static int hashCodeWithoutDatastoreIdentity(final VulnerableSoftware vs) {
        return Objects.hash(
                vs.getPurl(),
                vs.getPurlType(),
                vs.getPurlNamespace(),
                vs.getPurlName(),
                vs.getPurlVersion(),
                vs.getPurlQualifiers(),
                vs.getPurlSubpath(),
                vs.getCpe22(),
                vs.getCpe23(),
                vs.getPart(),
                vs.getVendor(),
                vs.getProduct(),
                vs.getVersion(),
                vs.getUpdate(),
                vs.getEdition(),
                vs.getLanguage(),
                vs.getSwEdition(),
                vs.getTargetSw(),
                vs.getTargetHw(),
                vs.getOther(),
                vs.getVersionEndExcluding(),
                vs.getVersionEndIncluding(),
                vs.getVersionStartExcluding(),
                vs.getVersionStartIncluding(),
                vs.isVulnerable()
        );
    }

    private static Predicate<VulnerableSoftware> distinctIgnoringDatastoreIdentity() {
        final var seen = new HashSet<Integer>();
        return vs -> seen.add(hashCodeWithoutDatastoreIdentity(vs));
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

        return cpeMatches.stream();
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
            LOGGER.debug("Encountered no modified CVEs");
            return false;
        }

        LOGGER.debug("Latest captured modification date: %s".formatted(lastModifiedDateTime));
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
