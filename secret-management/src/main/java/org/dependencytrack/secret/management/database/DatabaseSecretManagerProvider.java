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
package org.dependencytrack.secret.management.database;

import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretManagerProvider;
import org.eclipse.microprofile.config.Config;

import javax.sql.DataSource;

/**
 * @since 5.0.0
 */
public final class DatabaseSecretManagerProvider implements SecretManagerProvider {

    private final DataSourceRegistry dataSourceRegistry;

    DatabaseSecretManagerProvider(DataSourceRegistry dataSourceRegistry) {
        this.dataSourceRegistry = dataSourceRegistry;
    }

    @SuppressWarnings("unused")
    public DatabaseSecretManagerProvider() {
        this(DataSourceRegistry.getInstance());
    }

    @Override
    public String name() {
        return DatabaseSecretManager.NAME;
    }

    @Override
    public SecretManager create(Config config, PageTokenEncoder pageTokenEncoder) {
        final var secretManagerConfig = new DatabaseSecretManagerConfig(config);

        final DataSource dataSource = dataSourceRegistry.get(secretManagerConfig.getDataSourceName());

        return new DatabaseSecretManager(
                dataSource,
                new Crypto(dataSource, secretManagerConfig),
                pageTokenEncoder);
    }

}
