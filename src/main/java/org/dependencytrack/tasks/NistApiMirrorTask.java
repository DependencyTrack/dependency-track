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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.common.util.ProxyConfig;
import alpine.common.util.ProxyUtil;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableUncaughtExceptionHandler;
import alpine.event.framework.Subscriber;
import alpine.model.ConfigProperty;
import io.github.jeremylong.openvulnerability.client.HttpAsyncClientSupplier;
import io.github.jeremylong.openvulnerability.client.nvd.CveItem;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import io.github.jeremylong.openvulnerability.client.nvd.NvdApiRetryStrategy;
import io.github.jeremylong.openvulnerability.client.nvd.NvdCveClient;
import io.github.jeremylong.openvulnerability.client.nvd.NvdCveClientBuilder;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.NTCredentials;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClientBuilder;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.routing.SystemDefaultRoutePlanner;
import org.dependencytrack.common.AlpineHttpProxySelector;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.NistApiMirrorEvent;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.listener.IndexingInstanceLifecycleListener;
import org.dependencytrack.persistence.listener.L2CacheEvictingInstanceLifecycleListener;
import org.dependencytrack.util.DebugDataEncryption;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static io.github.jeremylong.openvulnerability.client.nvd.NvdCveClientBuilder.aNvdCveApi;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.datanucleus.PropertyNames.PROPERTY_RETAIN_VALUES;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_KEY;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_URL;
import static org.dependencytrack.parser.nvd.api20.ModelConverter.convert;
import static org.dependencytrack.parser.nvd.api20.ModelConverter.convertConfigurations;

/**
 * A {@link Subscriber} that mirrors the content of the NVD through the NVD API 2.0.
 *
 * @since 4.10.0
 */
public class NistApiMirrorTask extends AbstractNistMirrorTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(NistApiMirrorTask.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
        if (!(e instanceof NistApiMirrorEvent)) {
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
                            return DebugDataEncryption.decryptAsString(encryptedApiKey);
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

        // NvdCveClient queues Futures for all to-be-fetched pages of the NVD API upfront.
        // Each future will perform an HTTP request, and provide the HTTP response as result.
        // Responses are only consumed and parsed by the client when NvdCveClient#next is called.
        // Responses are pretty large as each page contains up to 2000 CVEs in JSON format.
        // If invocations of #next are too infrequent, unconsumed responses will pile up in memory.
        //
        // In an attempt to prevent unconsumed responses from staying around for too long,
        // we utilize this task's thread solely for converting them to our internal object model.
        // Actual synchronization with the database is offloaded to a separate executor thread.
        // This way, response objects can be GC'd quicker, significantly reducing memory footprint.
        final BasicThreadFactory factory = new BasicThreadFactory.Builder()
                .namingPattern(getClass().getSimpleName() + "-%d")
                .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                .build();

        final long startTimeNs = System.nanoTime();
        final var numMirrored = new AtomicInteger(0);
        ZonedDateTime lastModified;
        try (final NvdCveClient client = createApiClient(apiUrl, apiKey, lastModifiedEpochSeconds)) {
            try (final var executor = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.SECONDS, new LinkedBlockingQueue<>(), factory)) {
                while (client.hasNext()) {
                    for (final DefCveItem defCveItem : client.next()) {
                        final CveItem cveItem = defCveItem.getCve();
                        if (cveItem == null) {
                            continue;
                        }

                        final Vulnerability vuln = convert(cveItem);
                        final List<VulnerableSoftware> vsList = convertConfigurations(cveItem.getId(), cveItem.getConfigurations());

                        executor.submit(() -> {
                            try (final var qm = new QueryManager().withL2CacheDisabled()) {
                                qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");
                                qm.getPersistenceManager().setProperty(PROPERTY_RETAIN_VALUES, "true");
                                qm.getPersistenceManager().addInstanceLifecycleListener(new IndexingInstanceLifecycleListener(Event::dispatch),
                                        Vulnerability.class, VulnerableSoftware.class);
                                qm.getPersistenceManager().addInstanceLifecycleListener(new L2CacheEvictingInstanceLifecycleListener(qm),
                                        AffectedVersionAttribution.class, Vulnerability.class, VulnerableSoftware.class);

                                final Vulnerability persistentVuln = synchronizeVulnerability(qm, vuln);
                                synchronizeVulnerableSoftware(qm, persistentVuln, vsList);
                            } catch (RuntimeException ex) {
                                LOGGER.error("An unexpected error occurred while processing %s".formatted(vuln.getVulnId()), ex);
                            } finally {
                                final int currentNumMirrored = numMirrored.incrementAndGet();
                                if (currentNumMirrored % 2000 == 0) { // Max page size of NVD API responses is 2000.
                                    final int currentMirroredPercentage = (currentNumMirrored * 100) / client.getTotalAvailable();
                                    LOGGER.info("Mirrored %d/%d CVEs (%d%%)".formatted(currentNumMirrored, client.getTotalAvailable(), currentMirroredPercentage));
                                }
                            }
                        });
                    }
                }
            }

            lastModified = client.getLastUpdated();
        } catch (Exception ex) {
            LOGGER.error("An unexpected error occurred while mirroring the contents of the National Vulnerability Database", ex);
            return;
        } finally {
            LOGGER.info("Mirroring of %d CVEs completed in %s".formatted(numMirrored.get(), Duration.ofNanos(System.nanoTime() - startTimeNs)));
        }

        if (updateLastModified(lastModified)) {
            Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
            Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, VulnerableSoftware.class));
        }

        Event.dispatch(new EpssMirrorEvent());
    }

    private static NvdCveClient createApiClient(final String apiUrl, final String apiKey, final long lastModifiedEpochSeconds) {
        final NvdCveClientBuilder clientBuilder = aNvdCveApi()
                .withHttpClientSupplier(new HttpClientSupplier(apiKey != null))
                .withEndpoint(apiUrl);
        if (apiKey != null) {
            clientBuilder.withApiKey(apiKey);
        } else {
            LOGGER.warn("No API key configured; Aggressive rate limiting to be expected");
        }
        if (lastModifiedEpochSeconds > 0) {
            final var start = ZonedDateTime.ofInstant(Instant.ofEpochSecond(lastModifiedEpochSeconds), ZoneOffset.UTC);
            clientBuilder.withLastModifiedFilter(start, start.plusDays(120));
            LOGGER.info("Mirroring CVEs that were modified since %s".formatted(start));
        } else {
            LOGGER.info("CVEs were not previously mirrored via NVD API; Will mirror all CVEs");
        }

        return clientBuilder.build();
    }

    private static boolean updateLastModified(final ZonedDateTime lastModifiedDateTime) {
        if (lastModifiedDateTime == null) {
            LOGGER.debug("Encountered no modified CVEs");
            return false;
        }

        LOGGER.debug("Latest captured modification date: %s".formatted(lastModifiedDateTime));
        try (final var qm = new QueryManager()) {
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

    private static final class HttpClientSupplier implements HttpAsyncClientSupplier {

        private final boolean isApiKeyProvided;

        private HttpClientSupplier(final boolean isApiKeyProvided) {
            this.isApiKeyProvided = isApiKeyProvided;
        }

        @Override
        public CloseableHttpAsyncClient get() {
            final ProxyConfig proxyConfig = ProxyUtil.getProxyConfig();
            final HttpAsyncClientBuilder clientBuilder = HttpAsyncClients.custom()
                    .setRetryStrategy(new NvdApiRetryStrategy(10, isApiKeyProvided ? 600L : 6500L))
                    .setRoutePlanner(new SystemDefaultRoutePlanner(new AlpineHttpProxySelector(proxyConfig)))
                    .useSystemProperties();

            if (proxyConfig != null && isNotBlank(proxyConfig.getUsername()) && isNotBlank(proxyConfig.getPassword())) {
                final var authScope = new AuthScope(null, proxyConfig.getHost(), proxyConfig.getPort(), null, null);
                final var credentialProvider = new BasicCredentialsProvider();
                if (proxyConfig.getDomain() != null) {
                    credentialProvider.setCredentials(authScope, new NTCredentials(proxyConfig.getUsername(),
                            proxyConfig.getPassword().toCharArray(), null, proxyConfig.getDomain()));
                } else {
                    credentialProvider.setCredentials(authScope, new UsernamePasswordCredentials(proxyConfig.getUsername(),
                            proxyConfig.getPassword().toCharArray()));
                }
                clientBuilder.setDefaultCredentialsProvider(credentialProvider);
            }

            return clientBuilder.build();
        }

    }

}
