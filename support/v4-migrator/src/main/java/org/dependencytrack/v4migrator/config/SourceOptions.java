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
 * Source-side connection options. Used by {@code extract} and {@code run}.
 */
public final class SourceOptions {

    @Option(names = "--source-url",
        description = "JDBC URL of the v4 source database (PostgreSQL or MSSQL).",
        required = true)
    public String sourceUrl;

    @Option(names = "--source-user", description = "Source DB username.")
    @Nullable
    public String sourceUser;

    @Option(names = "--source-pass",
        description = "Source DB password. Pass without a value to be prompted interactively.",
        interactive = true,
        arity = "0..1")
    @Nullable
    public String sourcePass;
}
