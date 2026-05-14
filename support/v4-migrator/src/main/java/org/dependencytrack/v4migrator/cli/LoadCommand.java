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
import org.dependencytrack.v4migrator.load.LoadPhase;
import org.jdbi.v3.core.Jdbi;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "load", description = "INSERT...SELECT staging.tgt_* into the v5 schema.")
public final class LoadCommand extends AbstractMigratorCommand {

    @Option(names = "--drop-staging",
        description = "Drop the staging schema after a successful load.")
    boolean dropStaging;

    @Override
    protected int execute(final Jdbi target) throws Exception {
        new LoadPhase(global, target, dropStaging).run();
        return ExitCode.OK;
    }

    @Override
    protected void printPlan() {
        System.out.println("  Phase:  load");
        System.out.println("  Staging schema: " + global.stagingSchema);
        System.out.println("  Drop staging after: " + dropStaging);
        System.out.println("  Tables to load (FK-respecting order, " + TableRegistry.loaded().size() + "):");
        TableRegistry.loaded().forEach(t -> System.out.println("    - " + t.name()));
    }
}
