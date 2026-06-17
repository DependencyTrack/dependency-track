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
package org.dependencytrack.dex;

import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.engine.migration.MigrationExecutor;
import org.dependencytrack.init.InitTask;
import org.dependencytrack.init.InitTaskContext;

import javax.sql.DataSource;

/**
 * @since 5.0.0
 */
public final class DexEngineDatabaseMigrationInitTask implements InitTask {

    private final DataSourceRegistry dataSourceRegistry;

    DexEngineDatabaseMigrationInitTask(DataSourceRegistry dataSourceRegistry) {
        this.dataSourceRegistry = dataSourceRegistry;
    }

    @SuppressWarnings("unused") // Used by ServiceLoader.
    public DexEngineDatabaseMigrationInitTask() {
        this(DataSourceRegistry.getInstance());
    }

    @Override
    public int priority() {
        return PRIORITY_HIGHEST - 5;
    }

    @Override
    public String name() {
        return "dex-engine-database-migration";
    }

    @Override
    public void execute(InitTaskContext ctx) throws Exception {
        final String dataSourceName = ctx.config()
                .getOptionalValue("dt.dex-engine.migration.datasource.name", String.class)
                .or(() -> ctx.config().getOptionalValue("dt.dex-engine.datasource.name", String.class))
                .orElseThrow(() -> new IllegalStateException("No datasource name configured"));

        final DataSource dataSource = dataSourceRegistry.get(dataSourceName);
        new MigrationExecutor(dataSource).execute();
    }

}
