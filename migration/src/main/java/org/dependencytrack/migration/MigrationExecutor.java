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
package org.dependencytrack.migration;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.jspecify.annotations.Nullable;

import javax.sql.DataSource;

public final class MigrationExecutor {

    private static final String LOCATION = "org/dependencytrack/migration";

    private final Flyway flyway;

    public MigrationExecutor(DataSource dataSource) {
        this(dataSource, null);
    }

    public MigrationExecutor(DataSource dataSource, @Nullable String targetVersion) {
        final FluentConfiguration cfg = Flyway.configure()
                .dataSource(dataSource)
                .baselineVersion("202605022031")
                .baselineOnMigrate(true)
                .cleanDisabled(true)
                .placeholderReplacement(false)
                .locations("classpath:" + LOCATION)
                .loggers("slf4j");
        if (targetVersion != null) {
            cfg.target(targetVersion);
        }
        this.flyway = cfg.load();
    }

    public void execute() {
        flyway.migrate();
    }

}
