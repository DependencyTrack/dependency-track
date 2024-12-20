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
package org.dependencytrack.tasks.repositories;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.model.ConfigProperty;
import alpine.persistence.ScopedCustomization;
import io.micrometer.core.instrument.Timer;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.RepositoryMetaEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.CacheStampedeBlocker;
import org.dependencytrack.util.DebugDataEncryption;
import org.dependencytrack.util.PurlUtil;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import javax.jdo.Query;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD;
import static org.dependencytrack.util.PersistenceUtil.isUniqueConstraintViolation;

public class RepositoryMetaAnalyzerTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(RepositoryMetaAnalyzerTask.class);
    private static final String LATEST_VERSION = "latestVersion";
    private static final String PUBLISHED_TIMESTAMP = "publishedTimestamp";
    private static final CacheStampedeBlocker<String, Void> cacheStampedeBlocker;

    private long cacheValidityPeriod;

    static {
        cacheStampedeBlocker = new CacheStampedeBlocker<>(
                "repositoryMetaCache",
                Config.getInstance().getPropertyAsInt(ConfigKey.REPO_META_ANALYZER_CACHE_STAMPEDE_BLOCKER_LOCK_BUCKETS),
                false,
                Config.getInstance().getPropertyAsInt(ConfigKey.REPO_META_ANALYZER_CACHE_STAMPEDE_BLOCKER_MAX_ATTEMPTS)
        );
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof final RepositoryMetaEvent event) {
            try (final var qm = new QueryManager()) {
                final ConfigProperty cacheValidityPeriodProperty = qm.getConfigProperty(
                        SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getGroupName(),
                        SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyName());
                cacheValidityPeriod = Long.parseLong(cacheValidityPeriodProperty.getPropertyValue());
            }

            LOGGER.debug("Analyzing component repository metadata");
            // TODO - Remove when https://github.com/DependencyTrack/dependency-track/issues/2110 is implemented
            Timer timer = Timer.builder("repository_meta_analyzer_task")
                    .description("Repository meta analyzer task timer")
                    .tags("event", event.getClass().getName(), "publisher", this.getClass().getName())
                    .register(Metrics.getRegistry());
            Timer.Sample recording = Timer.start();
            if (event.getComponents().isPresent()) {
                try (QueryManager qm = new QueryManager()) {
                    final List<Component> components = event.getComponents().get();
                    // Refreshing the object by querying for it again is preventative
                    LOGGER.info("Performing component repository metadata analysis against " + components.size() + " components");
                    for (final Component component : components) {
                        analyze(qm, qm.getObjectById(Component.class, component.getId()));
                    }
                    LOGGER.info("Completed component repository metadata analysis against " + components.size() + " components");
                }
            } else {
                LOGGER.info("Analyzing portfolio component repository metadata");
                try (final QueryManager qm = new QueryManager()) {
                    List<Component> components = fetchNextComponentBatch(qm, null);
                    while (!components.isEmpty()) {
                        final long lastId = components.getLast().getId();

                        LOGGER.debug("Analyzing batch of %d components".formatted(components.size()));
                        for (final Component component : components) {
                            analyze(qm, component);
                        }

                        // Remove components, analysis cache, and meta components from
                        // the L1 cache to prevent it from growing too large.
                        qm.getPersistenceManager().evictAll(false, Component.class);
                        qm.getPersistenceManager().evictAll(false, ComponentAnalysisCache.class);
                        qm.getPersistenceManager().evictAll(false, RepositoryMetaComponent.class);

                        components = fetchNextComponentBatch(qm, lastId);
                    }
                }
                LOGGER.info("Portfolio component repository metadata analysis complete");
            }
            recording.stop(timer);
            LOGGER.debug("Component repository metadata analysis complete");
        }
    }

    private void analyze(final QueryManager qm, final Component component) {
        LOGGER.debug("Analyzing component: " + component.getUuid());
        final IMetaAnalyzer analyzer = IMetaAnalyzer.build(component);
        if (RepositoryType.UNSUPPORTED != analyzer.supportedRepositoryType() && !isRepositoryMetaComponentStillValid(qm, analyzer.supportedRepositoryType(), component.getPurl().getNamespace(), component.getPurl().getName())) {
            Callable<Void> cacheLoader = () -> {
                analyze(qm, component, analyzer);
                return null;
            };
            boolean cacheStampedeBlockerEnabled = Config.getInstance().getPropertyAsBoolean(ConfigKey.REPO_META_ANALYZER_CACHE_STAMPEDE_BLOCKER_ENABLED);
            if (cacheStampedeBlockerEnabled) {
                cacheStampedeBlocker.readThroughOrPopulateCache(PurlUtil.silentPurlCoordinatesOnly(component.getPurl()).toString(), cacheLoader);
            } else {
                try {
                    cacheLoader.call();
                } catch (Exception e) {
                    LOGGER.warn("Error while fetching component meta model for component(id=" + component.getId() + "; purl=" + component.getPurl() + ") : " + e.getMessage(), e);
                }
            }
        }
    }

    private void analyze(final QueryManager qm, final Component component, final IMetaAnalyzer analyzer) {
        // Retrieve existing Component Analysis Cache in one query :- There will be either no cac or cac without "latestVersion" (otherwise a RepositoryMetaModel would have already been created).
        // Caching cac without "latestVersion" allow avoiding performing the same call to repository over and over.
        final Map<String, ComponentAnalysisCache> cacByHost = new HashMap<>();
        List<ComponentAnalysisCache> cacList = qm.getComponentAnalysisCache(ComponentAnalysisCache.CacheType.REPOSITORY, analyzer.supportedRepositoryType().name(), PurlUtil.silentPurlCoordinatesOnly(component.getPurl()).toString());
        if (cacList != null && cacList.size() > 0) {
            cacList.stream().forEach(cac -> cacByHost.put(cac.getTargetHost(), cac));
        }
        for (final Repository repository : qm.getAllRepositoriesOrdered(analyzer.supportedRepositoryType())) {
            // Moved the identification of internal components from the isApplicable() method from the Meta Analyzers
            // themselves (which was introduced in https://github.com/DependencyTrack/dependency-track/pull/512)
            // and made a global decision here instead. Internal components should only be analyzed using internal
            // repositories. Non-internal components should only be analyzed with non-internal repositories. We do not
            // want non-internal components being analyzed with internal repositories as internal repositories are not
            // the source of truth for these components, even if the repository acts as a proxy to the source of truth.
            // This cannot be assumed.
            if (repository.isEnabled() && ((component.isInternal() && repository.isInternal()) || (!component.isInternal() && !repository.isInternal()))) {
                String purl = component.getPurl().toString();
                ComponentAnalysisCache cac = cacByHost.get(repository.getUrl());
                MetaModel model = new MetaModel(component);
                if (cac != null && isCacheCurrent(cac, component.getPurl().toString())) {
                    LOGGER.debug("Building repository Metamodel from cache for " + purl);
                    model.setLatestVersion(StringUtils.trimToNull(cac.getResult().getString(LATEST_VERSION)));
                    model.setPublishedTimestamp(Date.from(Instant.ofEpochMilli(cac.getResult().getJsonNumber(PUBLISHED_TIMESTAMP).longValue())));
                } else {
                    LOGGER.debug("Analyzing component: " + component.getUuid() + " using repository: "
                            + repository.getIdentifier() + " (" + repository.getType() + ")");

                    if (Boolean.TRUE.equals(repository.isAuthenticationRequired())) {
                        try {
                            LOGGER.error("decrypting credentials");
                            String decryptedPassword = null;
                            String decryptedBearerToken = null;
                            if (repository.getBearerToken() != null) {
                                decryptedBearerToken = DebugDataEncryption.decryptAsString(repository.getBearerToken());
                            }
                            if (repository.getPassword() != null) {
                                decryptedPassword = DebugDataEncryption.decryptAsString(repository.getPassword());
                            }
                            analyzer.setCredentials(repository.getUsername(), decryptedPassword, decryptedBearerToken);
                        } catch (Exception e) {
                            LOGGER.error("Failed decrypting password for repository: " + repository.getIdentifier(), e);
                        }
                    }
                    analyzer.setRepositoryBaseUrl(repository.getUrl());
                    model = analyzer.analyze(component);

                    try {
                        qm.updateComponentAnalysisCache(ComponentAnalysisCache.CacheType.REPOSITORY, repository.getUrl(), repository.getType().name(), PurlUtil.silentPurlCoordinatesOnly(component.getPurl()).toString(), new Date(), buildRepositoryComponentAnalysisCacheResult(model));
                    } catch (RuntimeException e) {
                        if (isUniqueConstraintViolation(e)) {
                            LOGGER.debug("""
                                    Encountered unique constraint violation while updating cache. \
                                    This happens when repository metadata analysis is executed for the same \
                                    component multiple times concurrently, and is safe to ignore. \
                                    [targetHost=%s, source=%s, target=%s]\
                                    """.formatted(repository.getUrl(), repository.getType(), PurlUtil.silentPurlCoordinatesOnly(component.getPurl())), e);
                            return;
                        } else {
                            throw e;
                        }
                    }
                }

                if (StringUtils.trimToNull(model.getLatestVersion()) != null) {
                    // Resolution from repository was successful. Update meta model
                    final RepositoryMetaComponent metaComponent = new RepositoryMetaComponent();
                    metaComponent.setRepositoryType(repository.getType());
                    metaComponent.setNamespace(component.getPurl().getNamespace());
                    metaComponent.setName(component.getPurl().getName());
                    metaComponent.setPublished(model.getPublishedTimestamp());
                    metaComponent.setLatestVersion(model.getLatestVersion());
                    metaComponent.setLastCheck(new Date());
                    try {
                        qm.synchronizeRepositoryMetaComponent(metaComponent);
                    } catch (RuntimeException e) {
                        if (isUniqueConstraintViolation(e)) {
                            LOGGER.debug("""
                                    Encountered unique constraint violation while synchronizing metadata. \
                                    This happens when repository metadata analysis is executed for the same \
                                    component multiple times concurrently, and is safe to ignore. \
                                    [targetHost=%s, source=%s, target=%s]\
                                    """.formatted(repository.getUrl(), repository.getType(), PurlUtil.silentPurlCoordinatesOnly(component.getPurl())), e);
                            return;
                        } else {
                            throw e;
                        }
                    }
                    // Since the component metadata found and captured from this repository, return from this
                    // method without attempting to query additional repositories.
                    LOGGER.debug("Found component metadata for: " + component.getUuid() + " using repository: "
                            + repository.getIdentifier() + " (" + repository.getType() + ")");
                    break;
                }
            } else {
                LOGGER.debug("Skipping analysis of component: " + component.getUuid() + " using repository: "
                        + repository.getIdentifier() + " (" + repository.getType() + ")");
            }
        }
    }

    private JsonObject buildRepositoryComponentAnalysisCacheResult(MetaModel model) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        String latestVersion = model.getLatestVersion() != null ? model.getLatestVersion() : "";
        Long published = model.getPublishedTimestamp() != null ? model.getPublishedTimestamp().getTime() : 0L;
        builder.add(LATEST_VERSION, Json.createValue(latestVersion));
        builder.add(PUBLISHED_TIMESTAMP, Json.createValue(published));
        return builder.build();
    }

    protected boolean isRepositoryMetaComponentStillValid(final QueryManager qm, final RepositoryType repositoryType, final String namespace, final String name) {
        boolean isRepositoryMetaComponentStillValid = false;
        RepositoryMetaComponent metaComponent = qm.getRepositoryMetaComponent(repositoryType, namespace, name);
        long delta = 0L;
        if (metaComponent != null) {
            final Date now = new Date();
            if (now.getTime() > metaComponent.getLastCheck().getTime()) {
                delta = now.getTime() - metaComponent.getLastCheck().getTime();
                isRepositoryMetaComponentStillValid = delta <= cacheValidityPeriod;
            }
        }
        if (isRepositoryMetaComponentStillValid) {
            LOGGER.debug("RepositoryMetaComponent has been checked in the last " + cacheValidityPeriod + " ms (precisely " + delta + " ms ago). Skipping analysis. (source: " + repositoryType.name() + " / Namespace: " + namespace + " / Name: " + name + ")");
        } else {
            LOGGER.debug("RepositoryMetaComponent has not been checked since " + cacheValidityPeriod + " ms. Analysis should be performed (source: " + repositoryType.name() + " / Namespace: " + namespace + " / Name: " + name + ")");
        }
        return isRepositoryMetaComponentStillValid;
    }

    protected boolean isCacheCurrent(ComponentAnalysisCache cac, String target) {
        boolean isCacheCurrent = false;
        long delta = 0L;
        if (cac != null) {
            final Date now = new Date();
            if (now.getTime() > cac.getLastOccurrence().getTime()) {
                delta = now.getTime() - cac.getLastOccurrence().getTime();
                isCacheCurrent = delta <= cacheValidityPeriod;
            }
        }
        if (isCacheCurrent) {
            LOGGER.debug("Cache is current. External repository call was made in the last " + cacheValidityPeriod + " ms (precisely " + delta + " ms ago). Skipping analysis. (target: " + target + ")");
        } else {
            LOGGER.debug("Cache is not current. External repository call was not made in the last " + cacheValidityPeriod + " ms. Analysis should be performed (target: " + target + ")");
        }
        return isCacheCurrent;
    }

    private List<Component> fetchNextComponentBatch(final QueryManager qm, final Long lastId) {
        final var filterConditions = new ArrayList<>(List.of(
                "project.active",
                "purl != null"));
        final var filterParams = new HashMap<String, Object>();
        if (lastId != null) {
            filterConditions.add("id < :lastId");
            filterParams.put("lastId", lastId);
        }

        final Query<Component> query = qm.getPersistenceManager().newQuery(Component.class);

        // NB: Set fetch group on PM level to avoid fields of the default fetch group from being loaded.
        try (var ignoredPersistenceCustomization = new ScopedCustomization(qm.getPersistenceManager())
                .withFetchGroup(Component.FetchGroup.REPO_META_ANALYSIS.name())) {
            query.setFilter(String.join(" && ", filterConditions));
            query.setNamedParameters(filterParams);
            query.setOrdering("id DESC");
            query.setRange(0, 1000);
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

}
