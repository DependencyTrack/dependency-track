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
package org.dependencytrack.v4migrator.verify;

import java.util.Map;
import java.util.Optional;

/**
 * Operator-facing explanations for tables whose v5 row count legitimately differs from the v4
 * source. These are the documented lossy transforms (dedup, filtering, retention) applied during
 * the transform phase; the reasons mirror the per-table Javadoc in
 * {@code org.dependencytrack.v4migrator.TableRegistry}.
 *
 * <p>Kept here (rather than as a field on {@code TableMigration}) so the explanations live next to
 * the verify reporting that surfaces them, without threading text through every registry record.
 * The {@code [Probes]} section already itemizes UUID/user/case-collision drops, so those are not
 * duplicated here.
 */
final class RowCountNotes {

    private static final Map<String, String> NOTES = Map.ofEntries(
        Map.entry("TEAM", "dedup by NAME"),
        Map.entry("TAG", "dedup by NAME"),
        Map.entry("OIDCGROUP", "dedup by NAME"),
        Map.entry("PROJECT", "dedup by (NAME, VERSION); invalid-UUID rows dropped"),
        Map.entry("PROJECT_METADATA", "one row per PROJECT_ID (latest by ID)"),
        Map.entry("DEPENDENCYMETRICS", "latest snapshot per key; retention cutoff applied"),
        Map.entry("PROJECTMETRICS", "latest snapshot per key; retention cutoff applied"),
        Map.entry("FINDINGATTRIBUTION", "one attribution per (component, vulnerability, analyzer)"),
        Map.entry("VULNERABLESOFTWARE", "dropped rows without vulnerability refs or with invalid UUID"),
        Map.entry("USER", "consolidated from MANAGED/LDAP/OIDC users; invalid rows skipped"),
        // Permission join tables: v4-only permissions are dropped during the rename remap, while
        // PORTFOLIO_ACCESS_CONTROL_BYPASS is fanned out for ACCESS_MANAGEMENT holders. The net delta
        // is a deterministic function of the remap, not a loss indicator either way.
        Map.entry("TEAMS_PERMISSIONS", "permissions remapped (v4-only dropped); BYPASS fan-out added; net delta expected"),
        Map.entry("USERS_PERMISSIONS", "permissions remapped (v4-only dropped); BYPASS fan-out added; net delta expected"),
        Map.entry("PROJECT_ACCESS_TEAMS", "dropped rows with NULL TEAM_ID; dedup on (PROJECT_ID, TEAM_ID)"),
        Map.entry("PROJECT_ACCESS_USERS", "derived from PROJECT_ACCESS_TEAMS join USERS_TEAMS; dedup on (PROJECT_ID, USER_ID)")
    );

    private RowCountNotes() {
    }

    static Optional<String> reasonFor(final String table) {
        return Optional.ofNullable(NOTES.get(table));
    }
}
