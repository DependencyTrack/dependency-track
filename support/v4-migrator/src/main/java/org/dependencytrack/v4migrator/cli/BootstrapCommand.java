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
package org.dependencytrack.v4migrator.cli;

import org.dependencytrack.migration.MigrationExecutor;
import org.dependencytrack.v4migrator.ExitCode;
import org.dependencytrack.v4migrator.config.Connections;
import org.dependencytrack.v4migrator.preflight.Preflight;
import org.dependencytrack.v4migrator.preflight.Preflight.Mode;
import org.jdbi.v3.core.Jdbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Command;

@Command(name = "bootstrap",
    description = "Apply the v5 Flyway schema to a fresh target database. "
        + "Run this once before 'extract' / 'run' against a new target.")
public final class BootstrapCommand extends AbstractMigratorCommand {

    private static final Logger LOGGER = LoggerFactory.getLogger(BootstrapCommand.class);

    @Override
    protected Mode preflightMode() {
        return Mode.PRE_BOOTSTRAP;
    }

    @Override
    protected int execute(final Jdbi target) {
        LOGGER.info("Applying v5 Flyway schema up to {}", Preflight.EXPECTED_FLYWAY_HEAD);
        new MigrationExecutor(Connections.targetDataSource(global), Preflight.EXPECTED_FLYWAY_HEAD).execute();

        final String head = target.withHandle(h ->
            h.createQuery("""
                    SELECT version FROM flyway_schema_history
                     WHERE success = TRUE AND version IS NOT NULL
                     ORDER BY installed_rank DESC LIMIT 1
                    """)
                .mapTo(String.class)
                .findOne()
                .orElse(null));
        if (!Preflight.EXPECTED_FLYWAY_HEAD.equals(head)) {
            LOGGER.error("Flyway head after bootstrap is '{}' but expected '{}'.",
                head, Preflight.EXPECTED_FLYWAY_HEAD);
            return ExitCode.SCHEMA_VERSION_MISMATCH;
        }
        LOGGER.info("Bootstrap complete. Flyway head = {}. Run 'extract' or 'run' next.", head);
        return ExitCode.OK;
    }

    @Override
    protected void printPlan() {
        System.out.println("  Phase:  bootstrap");
        System.out.println("  Target Flyway head to apply: " + Preflight.EXPECTED_FLYWAY_HEAD);
    }
}
