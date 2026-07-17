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

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.micrometer.core.instrument.Metrics;
import org.postgresql.ds.PGSimpleDataSource;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * @since 5.0.0
 */
final class DataSourceFactory {

    private DataSourceFactory() {
    }

    static DataSource createDataSource(DataSourceConfig config) {
        final String appName = "dependency-track[%s]".formatted(config.getName());

        if (config.isPoolEnabled()) {
            final var hikariConfig = new HikariConfig();
            hikariConfig.setPoolName(config.getName());
            hikariConfig.setJdbcUrl(config.getUrl());
            hikariConfig.addDataSourceProperty("ApplicationName", appName);
            hikariConfig.addDataSourceProperty("reWriteBatchedInserts", "true");
            hikariConfig.addDataSourceProperty("tcpKeepAlive", "true");
            hikariConfig.setMaximumPoolSize(config.getPoolMaxSize());
            hikariConfig.setMinimumIdle(config.getPoolMinIdle());
            hikariConfig.setMetricRegistry(Metrics.globalRegistry);
            config.getUsername().ifPresent(hikariConfig::setUsername);
            getPassword(config).ifPresent(hikariConfig::setPassword);
            config.getConnectionTimeoutMillis().ifPresent(hikariConfig::setConnectionTimeout);
            config.getPoolIdleTimeoutMillis().ifPresent(hikariConfig::setIdleTimeout);
            config.getPoolLeakDetectionThresholdMillis().ifPresent(hikariConfig::setLeakDetectionThreshold);
            config.getPoolMaxLifetimeMillis().ifPresent(hikariConfig::setMaxLifetime);
            config.getPoolKeepaliveIntervalMillis().ifPresent(hikariConfig::setKeepaliveTime);
            return new HikariDataSource(hikariConfig);
        }

        final var dataSource = new PGSimpleDataSource();

        // NB: These properties must be set BEFORE setUrl is called,
        // as the driver only then loops over all properties and applies
        // them to the URL. Setting the URL first would cause these
        // properties to no-op.
        dataSource.setApplicationName(appName);
        config.getConnectionTimeoutMillis()
                .map(TimeUnit.MILLISECONDS::toSeconds)
                .map(Math::toIntExact)
                .ifPresent(dataSource::setConnectTimeout);
        dataSource.setReWriteBatchedInserts(true);
        dataSource.setTcpKeepAlive(true);

        dataSource.setUrl(config.getUrl());
        config.getUsername().ifPresent(dataSource::setUser);
        getPassword(config).ifPresent(dataSource::setPassword);

        return dataSource;
    }

    private static Optional<String> getPassword(DataSourceConfig config) {
        final Path passwordFilePath = config.getPasswordFilePath().orElse(null);
        if (passwordFilePath != null) {
            try {
                return Optional.of(Files.readString(passwordFilePath).trim());
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to read password file", e);
            }
        }

        return config.getPassword();
    }

}
