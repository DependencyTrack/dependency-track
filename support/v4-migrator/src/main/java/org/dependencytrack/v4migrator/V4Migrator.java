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
package org.dependencytrack.v4migrator;

import org.dependencytrack.v4migrator.cli.BootstrapCommand;
import org.dependencytrack.v4migrator.cli.CleanupCommand;
import org.dependencytrack.v4migrator.cli.ExtractCommand;
import org.dependencytrack.v4migrator.cli.LoadCommand;
import org.dependencytrack.v4migrator.cli.RunCommand;
import org.dependencytrack.v4migrator.cli.TransformCommand;
import org.dependencytrack.v4migrator.cli.VerifyCommand;
import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
    name = "v4-migrator",
    description = "Dependency-Track v4 → v5 data migration CLI.",
    mixinStandardHelpOptions = true,
    versionProvider = V4Migrator.VersionProvider.class,
    subcommands = {
        BootstrapCommand.class,
        ExtractCommand.class,
        TransformCommand.class,
        LoadCommand.class,
        VerifyCommand.class,
        CleanupCommand.class,
        RunCommand.class,
    }
)
public final class V4Migrator {

    public static void main(final String[] args) {
        final int exitCode = new CommandLine(new V4Migrator()).execute(args);
        System.exit(exitCode);
    }

    static final class VersionProvider implements CommandLine.IVersionProvider {
        @Override
        public String[] getVersion() {
            final String version = V4Migrator.class.getPackage().getImplementationVersion();
            return new String[]{version != null ? version : "dev"};
        }
    }
}
