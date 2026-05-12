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
import org.jdbi.v3.core.Jdbi;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;

@Command(name = "extract", description = "Pull v4 source rows into staging.src_*.")
public final class ExtractCommand extends AbstractMigratorCommand {

    @Mixin
    SourceOptions sourceOpts = new SourceOptions();

    @Mixin
    MetricsRetentionOptions metricsOpts = new MetricsRetentionOptions();

    @Override
    protected SourceOptions source() {
        return sourceOpts;
    }

    @Override
    protected int execute(final Jdbi target) throws Exception {
        new ExtractPhase(global, sourceOpts, target, metricsOpts.metricsRetentionDays).run();
        return ExitCode.OK;
    }

    @Override
    protected void printPlan() {
        System.out.println("  Phase:  extract");
        System.out.println("  Source: " + sourceOpts.sourceUrl);
        System.out.println("  Target staging schema: " + global.stagingSchema);
        System.out.println("  Tables to extract (" + TableRegistry.extracted().size() + "):");
        TableRegistry.extracted().forEach(t -> System.out.println("    - " + t.name()));
    }
}
