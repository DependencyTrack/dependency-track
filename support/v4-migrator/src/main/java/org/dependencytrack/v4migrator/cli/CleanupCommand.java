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
import org.dependencytrack.v4migrator.config.Connections;
import org.dependencytrack.v4migrator.config.GlobalOptions;
import org.jdbi.v3.core.Jdbi;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;

import java.util.concurrent.Callable;

@Command(name = "cleanup", description = "Drop the staging schema.")
public final class CleanupCommand implements Callable<Integer> {

    @Mixin
    GlobalOptions global = new GlobalOptions();

    @Override
    public Integer call() {
        final LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
        ctx.getLogger("org.dependencytrack.v4migrator").setLevel(Level.toLevel(global.logLevel, Level.INFO));

        if (global.dryRun) {
            System.out.println("Dry-run: would DROP SCHEMA IF EXISTS \"" + global.stagingSchema + "\" CASCADE");
            return ExitCode.OK;
        }

        final Jdbi target = Connections.targetJdbi(global);
        target.useHandle(h -> h.execute("DROP SCHEMA IF EXISTS \"" + global.stagingSchema + "\" CASCADE"));
        return ExitCode.OK;
    }
}
