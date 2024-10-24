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
package org.dependencytrack.observability;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.server.persistence.PersistenceManagerFactory;
import io.github.nscuro.datanucleus.cache.caffeine.CaffeineLevel2Cache;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import org.datanucleus.api.jdo.JDODataStoreCache;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.datanucleus.cache.Level2Cache;

import javax.jdo.PersistenceManager;
import java.util.concurrent.TimeUnit;

import static org.datanucleus.PropertyNames.PROPERTY_CACHE_L2_STATISTICS_ENABLED;
import static org.datanucleus.PropertyNames.PROPERTY_CACHE_L2_TYPE;

public class MeterRegistryCustomizer implements alpine.common.metrics.MeterRegistryCustomizer {

    private static final Logger LOGGER = Logger.getLogger(MeterRegistryCustomizer.class);

    @Override
    public void accept(final MeterRegistry meterRegistry) {
        if (!Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            return;
        }

        maybeRegisterCaffeineLevel2CacheMetrics(meterRegistry);
    }

    /**
     * Register Caffeine-specific metrics for the DataNucleus L2 cache, if and only if
     * Caffeine is configured as L2 cache via {@code datanucleus.cache.level2.type}.
     * <p>
     * DataNucleus' {@link Level2Cache} doesn't expose any more statistics than the size,
     * but we would like to monitor hit, miss, and invalidation metrics.
     */
    @SuppressWarnings("BusyWait")
    private void maybeRegisterCaffeineLevel2CacheMetrics(final MeterRegistry meterRegistry) {
        // The customizer executes before the persistence context is created.
        // Use a separate thread to wait for the persistence context to become available,
        // and register cache metrics once it is.
        //
        // To prevent the thread from waiting forever (should not happen),
        // cap the max wait duration at 15 seconds.
        final long timeoutMs = TimeUnit.SECONDS.toMillis(15);

        final var thread = new Thread(() -> {
            final long startTimeMs = System.currentTimeMillis();

            while ((System.currentTimeMillis() - startTimeMs) < timeoutMs) {
                try (final PersistenceManager pm = PersistenceManagerFactory.createPersistenceManager()) {
                    final var pmf = (JDOPersistenceManagerFactory) pm.getPersistenceManagerFactory();
                    if (!"caffeine".equals(pmf.getProperties().get(PROPERTY_CACHE_L2_TYPE))) {
                        LOGGER.debug("Not registering Caffeine L2 cache metrics, because %s is not \"caffeine\""
                                .formatted(PROPERTY_CACHE_L2_TYPE));
                        return;
                    }
                    if (!Boolean.TRUE.equals(pmf.getProperties().get(PROPERTY_CACHE_L2_STATISTICS_ENABLED))) {
                        LOGGER.debug("Not registering Caffeine L2 cache metrics, because %s is not enabled"
                                .formatted(PROPERTY_CACHE_L2_STATISTICS_ENABLED));
                        return;
                    }

                    final var dataStoreCache = (JDODataStoreCache) pmf.getDataStoreCache();
                    if (dataStoreCache.getLevel2Cache() instanceof final CaffeineLevel2Cache level2Cache) {
                        new CaffeineCacheMetrics<>(
                                level2Cache.getCaffeineCache(),
                                /* cacheName */ "datanucleus_second_level",
                                /* tags */ null)
                                .bindTo(meterRegistry);
                        LOGGER.debug("Registered Caffeine L2 cache metrics");
                    }

                    break;
                } catch (IllegalStateException e) {
                    // Persistence context not created yet.
                }

                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Thread was interrupted while sleeping", e);
                }
            }
        });
        thread.start();
    }

}
