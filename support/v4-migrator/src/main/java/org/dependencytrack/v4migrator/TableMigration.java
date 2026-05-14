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

import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * One entry in the migration pipeline. Each entry can participate in any combination of the
 * three phases:
 * <ul>
 *   <li>Extract: requires {@code srcCreateDdl}, {@code extractSelect}, and
 *       {@code extractColumns}. A {@code null} {@code srcCreateDdl} signals a pure derived
 *       table with no direct v4 source (e.g. {@code USER}, {@code PROJECT_HIERARCHY}).</li>
 *   <li>Transform: requires {@code transformSql}. A {@code null} value signals a v4-only
 *       source table consumed exclusively by downstream derived transforms (e.g.
 *       {@code LDAPUSER}).</li>
 *   <li>Load: requires {@code loadSql}. A {@code null} value signals a table that does not
 *       have a 1:1 v5 counterpart (e.g. {@code MANAGEDUSER}, which is consumed by {@code USER}).</li>
 * </ul>
 */
public record TableMigration(
    String name,
    @Nullable String srcCreateDdl,
    @Nullable String extractSelect,
    @Nullable List<String> extractColumns,
    @Nullable String transformSql,
    @Nullable String loadSql
) {

    public boolean hasExtract() {
        return srcCreateDdl != null && extractSelect != null && extractColumns != null;
    }

    public boolean hasTransform() {
        return transformSql != null;
    }

    public boolean hasLoad() {
        return loadSql != null;
    }
}
