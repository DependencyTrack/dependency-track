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
package org.dependencytrack.common.datasource;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @since 5.0.0
 */
public final class DataSourceRegistry {

    private static final DataSourceRegistry INSTANCE = new DataSourceRegistry();
    private static final Logger LOGGER = LoggerFactory.getLogger(DataSourceRegistry.class);

    private final Config config;
    private final Map<String, DataSource> dataSourceByName;

    private DataSourceRegistry() {
        this(ConfigProvider.getConfig());
    }

    public DataSourceRegistry(final Config config) {
        this.config = config;
        this.dataSourceByName = new ConcurrentHashMap<>();
    }

    public static DataSourceRegistry getInstance() {
        return INSTANCE;
    }

    /**
     * Get a data source from the registry, creating it if it does not exist yet.
     *
     * @param name Name of the data source.
     * @return The data source.
     */
    public DataSource get(final String name) {
        return dataSourceByName.computeIfAbsent(name, dataSourceName -> {
            LOGGER.info("Creating data source {}", dataSourceName);
            return DataSourceFactory.createDataSource(new DataSourceConfig(config, name));
        });
    }

    /**
     * Get the default data source from the registry, creating it if it does not exist yet.
     *
     * @return The data source.
     */
    public DataSource getDefault() {
        return get("default");
    }

    /**
     * Removes all data sources from the registry and closes them.
     *
     * @see #close(String)
     */
    public void closeAll() {
        dataSourceByName.keySet().forEach(this::close);
    }

    /**
     * Removes a data source from the registry and closes it.
     *
     * @param name Name of the data source to close.
     */
    public void close(final String name) {
        final DataSource dataSource = dataSourceByName.remove(name);
        if (dataSource == null) {
            return;
        }

        LOGGER.info("Closing data source {}", name);
        if (dataSource instanceof final Closeable closeable) {
            try {
                closeable.close();
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to close data source " + name, e);
            }
        }
    }

    void add(final String name, final DataSource dataSource) {
        final DataSource existing = dataSourceByName.putIfAbsent(name, dataSource);
        if (existing != null) {
            throw new IllegalStateException(
                    "A data source with name %s was already registered".formatted(name));
        }
    }

    Map<String, DataSource> getAll() {
        return Map.copyOf(dataSourceByName);
    }

}
