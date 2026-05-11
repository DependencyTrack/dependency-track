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

import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Map;

/**
 * @since 5.0.0
 */
@Readiness
public final class DataSourceHealthCheck implements HealthCheck {

    private static final Logger LOGGER = LoggerFactory.getLogger(DataSourceHealthCheck.class);

    private final DataSourceRegistry dataSourceRegistry;

    DataSourceHealthCheck(final DataSourceRegistry dataSourceRegistry) {
        this.dataSourceRegistry = dataSourceRegistry;
    }

    @SuppressWarnings("unused")
    public DataSourceHealthCheck() {
        this(DataSourceRegistry.getInstance());
    }

    @Override
    public HealthCheckResponse call() {
        final var responseBuilder = HealthCheckResponse.named("dataSources");

        boolean isUp = true;
        for (final Map.Entry<String, DataSource> entry : dataSourceRegistry.getAll().entrySet()) {
            final String name = entry.getKey();
            final DataSource dataSource = entry.getValue();

            LOGGER.debug("Checking health of data source {}", name);
            try (final Connection ignored = dataSource.getConnection()) {
                responseBuilder.withData(name, HealthCheckResponse.Status.UP.name());
            } catch (SQLException | RuntimeException e) {
                responseBuilder.withData(name, HealthCheckResponse.Status.DOWN.name());
                isUp = false;
            }
        }

        return responseBuilder.status(isUp).build();
    }

}
