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
package org.dependencytrack.v4migrator.config;

import org.jspecify.annotations.Nullable;
import picocli.CommandLine.Option;

/**
 * Options shared across CLI commands.
 */
public final class GlobalOptions {

    @Option(names = "--target-url",
            description = "JDBC URL of the v5 target PostgreSQL.",
            required = true)
    public String targetUrl;

    @Option(names = "--target-user", description = "Target DB username.")
    @Nullable
    public String targetUser;

    @Option(names = "--target-pass",
            description = "Target DB password. Pass without a value to be prompted interactively.",
            interactive = true,
            arity = "0..1")
    @Nullable
    public String targetPass;

    @Option(names = "--staging-schema",
            description = "Schema name for migrator staging. Default: ${DEFAULT-VALUE}.",
            defaultValue = "dt_v4_migration",
            converter = SchemaNameConverter.class)
    public String stagingSchema;

    @Option(names = "--log-level",
            description = "Log level (TRACE, DEBUG, INFO, WARN, ERROR). Default: ${DEFAULT-VALUE}.",
            defaultValue = "INFO")
    public String logLevel;

    @Option(names = "--dry-run",
            description = "Run preflight and print a plan; do not mutate any database.")
    public boolean dryRun;

    @Option(names = "--socket-timeout",
            description = "Upper bound, in seconds, on any single PostgreSQL network read. "
                + "When set, a stalled connection (dropped peer, broken firewall flow) surfaces "
                + "as a SQLException instead of hanging indefinitely. Must exceed the longest "
                + "expected single statement. 0 disables. Default: ${DEFAULT-VALUE}.",
            defaultValue = "0")
    public int socketTimeoutSeconds;

}
