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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import org.dependencytrack.v4migrator.ExitCode;
import org.dependencytrack.v4migrator.config.GlobalOptions;
import org.dependencytrack.v4migrator.config.SourceOptions;
import org.dependencytrack.v4migrator.preflight.Preflight;
import org.dependencytrack.v4migrator.preflight.Preflight.Mode;
import org.dependencytrack.v4migrator.preflight.PreflightResult;
import org.jdbi.v3.core.Jdbi;
import org.jspecify.annotations.Nullable;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Mixin;

import java.util.concurrent.Callable;

import static org.dependencytrack.v4migrator.config.Connections.targetJdbi;

abstract class AbstractMigratorCommand implements Callable<Integer> {

    @Mixin
    GlobalOptions global = new GlobalOptions();

    @Override
    public final Integer call() throws Exception {
        configureLogging(global.logLevel);
        try {
            global.validate();
        } catch (final IllegalArgumentException e) {
            System.err.println(e.getMessage());
            return ExitCode.PREFLIGHT_FAILED;
        }
        final Jdbi target = targetJdbi(global);
        final PreflightResult preflight = new Preflight(target, source(), global, preflightMode()).run();
        if (!preflight.ok()) {
            return preflight.exitCode();
        }
        if (global.dryRun) {
            System.out.println("Dry-run: preflight passed. Plan:");
            printPlan();
            return ExitCode.OK;
        }
        return execute(target);
    }

    /**
     * Returns the source connection options for commands that touch the v4 source.
     * Default is {@code null} (target-only commands).
     */
    protected @Nullable SourceOptions source() {
        return null;
    }

    /**
     * Preflight mode for this command. Most commands operate on a fully bootstrapped target
     * and should use {@link Mode#DEFAULT}. The {@code bootstrap} command overrides this to
     * {@link Mode#PRE_BOOTSTRAP} since it runs before Flyway has been applied.
     */
    protected Mode preflightMode() {
        return Mode.DEFAULT;
    }

    /**
     * The command body; runs only when preflight passes and {@code --dry-run} is not set.
     */
    protected abstract int execute(Jdbi target) throws Exception;

    /**
     * Print a high-level plan for {@code --dry-run}. Subclasses override.
     */
    protected void printPlan() {
        System.out.println("  (no plan available for this command)");
    }

    private static void configureLogging(final String level) {
        final LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
        ctx.getLogger("org.dependencytrack.v4migrator").setLevel(Level.toLevel(level, Level.INFO));
    }
}
