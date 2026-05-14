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
import org.dependencytrack.v4migrator.verify.VerifyPhase;
import org.jdbi.v3.core.Jdbi;
import picocli.CommandLine.Command;

@Command(name = "verify", description = "Advisory post-load checks.")
public final class VerifyCommand extends AbstractMigratorCommand {

    @Override
    protected int execute(final Jdbi target) throws Exception {
        new VerifyPhase(global, target).run();
        return ExitCode.OK;
    }

    @Override
    protected void printPlan() {
        System.out.println("  Phase:  verify (read-only)");
        System.out.println("  Staging schema: " + global.stagingSchema);
    }
}
