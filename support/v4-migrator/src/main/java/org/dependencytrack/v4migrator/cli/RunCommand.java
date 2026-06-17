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

import org.dependencytrack.v4migrator.ExitCode;
import org.dependencytrack.v4migrator.TableRegistry;
import org.dependencytrack.v4migrator.config.MetricsRetentionOptions;
import org.dependencytrack.v4migrator.config.SourceOptions;
import org.dependencytrack.v4migrator.extract.ExtractPhase;
import org.dependencytrack.v4migrator.load.LoadPhase;
import org.dependencytrack.v4migrator.transform.TransformPhase;
import org.jdbi.v3.core.Jdbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

@Command(name = "run", description = "extract + transform + load in one go.")
public final class RunCommand extends AbstractMigratorCommand {

    private static final Logger LOGGER = LoggerFactory.getLogger(RunCommand.class);

    @Mixin
    SourceOptions sourceOpts = new SourceOptions();

    @Mixin
    MetricsRetentionOptions metricsOpts = new MetricsRetentionOptions();

    @Option(names = "--sample",
        description = "Sample mode: extract at most N rows per table.")
    long sampleRowsPerTable = Long.MAX_VALUE;

    @Option(names = "--drop-staging",
        description = "Drop the staging schema after a successful load.")
    boolean dropStaging;

    @Override
    protected SourceOptions source() {
        return sourceOpts;
    }

    @Override
    protected int execute(final Jdbi target) throws Exception {
        new ExtractPhase(global, sourceOpts, target, sampleRowsPerTable,
            metricsOpts.metricsRetentionDays).run();
        new TransformPhase(global, target).run();
        new LoadPhase(global, target, dropStaging).run();
        LOGGER.info("Migration completed: extract + transform + load finished. "
            + "Run 'verify' to review row counts and probes.");
        return ExitCode.OK;
    }

    @Override
    protected void printPlan() {
        System.out.println("  Phase:  run (extract + transform + load)");
        System.out.println("  Source: " + sourceOpts.sourceUrl);
        System.out.println("  Target staging schema: " + global.stagingSchema);
        System.out.println("  Drop staging after: " + dropStaging);
        System.out.println("  Sample rows per table: "
            + (sampleRowsPerTable == Long.MAX_VALUE ? "unlimited" : sampleRowsPerTable));
        System.out.println("  Tables (extract " + TableRegistry.extracted().size()
            + ", transform " + TableRegistry.transformed().size()
            + ", load " + TableRegistry.loaded().size() + ")");
    }
}
