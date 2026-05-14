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

import java.util.regex.Pattern;

/**
 * Options shared across CLI commands.
 */
public final class GlobalOptions {

    /**
     * PostgreSQL unquoted-identifier syntax minus the locale-dependent letter ranges:
     * leading letter or underscore, followed by letters, digits, underscores, or {@code $}.
     * Max length 63 bytes ({@code NAMEDATALEN - 1}). The staging schema name is splice-formatted
     * into SQL strings throughout the migrator, so the value must not contain anything that could
     * close an identifier (quote, semicolon, dash, etc.) or anything the parser would treat as
     * additional tokens.
     */
    private static final Pattern SCHEMA_NAME_PATTERN = Pattern.compile("^[A-Za-z_][A-Za-z0-9_$]{0,62}$");

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
            defaultValue = "dt_v4_migration")
    public String stagingSchema;

    @Option(names = "--log-level",
            description = "Log level (TRACE, DEBUG, INFO, WARN, ERROR). Default: ${DEFAULT-VALUE}.",
            defaultValue = "INFO")
    public String logLevel;

    @Option(names = "--dry-run",
            description = "Run preflight and print a plan; do not mutate any database.")
    public boolean dryRun;

    /**
     * Rejects a staging schema name that does not match the safe-identifier pattern.
     * The name is splice-formatted into SQL throughout the migrator, so anything outside
     * the unquoted-identifier syntax would allow injection.
     */
    public void validate() {
        if (stagingSchema == null || !SCHEMA_NAME_PATTERN.matcher(stagingSchema).matches()) {
            throw new IllegalArgumentException(
                    "--staging-schema must match [A-Za-z_][A-Za-z0-9_$]* and be 1-63 characters; got '"
                            + stagingSchema + "'");
        }
    }
}
