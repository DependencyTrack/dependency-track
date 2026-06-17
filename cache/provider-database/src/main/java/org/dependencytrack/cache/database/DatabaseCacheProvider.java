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
package org.dependencytrack.cache.database;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.api.CacheProvider;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import javax.sql.DataSource;
import java.time.Duration;

/**
 * @since 5.0.0
 */
public final class DatabaseCacheProvider implements CacheProvider {

    private final Config config;
    private final DataSourceRegistry dataSourceRegistry;
    private final MeterRegistry meterRegistry;

    DatabaseCacheProvider(
            Config config,
            DataSourceRegistry dataSourceRegistry,
            MeterRegistry meterRegistry) {
        this.config = config;
        this.dataSourceRegistry = dataSourceRegistry;
        this.meterRegistry = meterRegistry;
    }

    @SuppressWarnings("unused") // Used by ServiceLoader.
    public DatabaseCacheProvider() {
        this(ConfigProvider.getConfig(), DataSourceRegistry.getInstance(), Metrics.globalRegistry);
    }

    @Override
    public String name() {
        return "database";
    }

    @Override
    public CacheManager create() {
        final String dataSourceName = config.getValue(
                "dt.cache.provider.database.datasource.name", String.class);
        final DataSource dataSource = dataSourceRegistry.get(dataSourceName);

        final var maintenanceWorker = new DatabaseCacheMaintenanceWorker(
                dataSource,
                config
                        .getOptionalValue("dt.cache.provider.database.maintenance.initial-delay-ms", long.class)
                        .map(Duration::ofMillis)
                        .orElse(Duration.ofMinutes(1)),
                config
                        .getOptionalValue("dt.cache.provider.database.maintenance.interval-ms", long.class)
                        .map(Duration::ofMillis)
                        .orElse(Duration.ofMinutes(5)));
        maintenanceWorker.start();

        return new DatabaseCacheManager(config, dataSource, meterRegistry, maintenanceWorker);
    }

}
