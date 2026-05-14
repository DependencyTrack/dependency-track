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
package org.dependencytrack.v4migrator.state;

import org.jdbi.v3.core.Jdbi;

/**
 * Manages the staging schema layout: the schema itself, {@code migration_state}, and
 * {@code migration_config}. Pipeline design §2.
 */
public final class StagingSchema {

    private final Jdbi target;
    private final String schema;

    public StagingSchema(final Jdbi target, final String schema) {
        this.target = target;
        this.schema = schema;
    }

    public String name() {
        return schema;
    }

    /**
     * Idempotently create the staging schema and migrator-owned tables.
     */
    public void ensure() {
        target.useHandle(h -> {
            h.execute("CREATE SCHEMA IF NOT EXISTS \"" + schema + "\"");
            h.execute("""
                CREATE TABLE IF NOT EXISTS "%s".migration_state (
                    table_name      TEXT NOT NULL,
                    phase           TEXT NOT NULL,
                    status          TEXT NOT NULL,
                    rows_processed  BIGINT NOT NULL DEFAULT 0,
                    started_at      TIMESTAMPTZ,
                    completed_at    TIMESTAMPTZ,
                    error_message   TEXT,
                    PRIMARY KEY (table_name, phase)
                )
                """.formatted(schema));
            h.execute("""
                CREATE TABLE IF NOT EXISTS "%s".migration_config (
                    key   TEXT PRIMARY KEY,
                    value TEXT
                )
                """.formatted(schema));
            h.execute("""
                CREATE TABLE IF NOT EXISTS "%s".probe_invalid_uuids (
                    table_name TEXT   NOT NULL,
                    orig_id    BIGINT NOT NULL,
                    bad_uuid   TEXT   NOT NULL,
                    PRIMARY KEY (table_name, orig_id)
                )
                """.formatted(schema));
            h.execute("""
                CREATE TABLE IF NOT EXISTS "%s".probe_skipped_users (
                    table_name TEXT   NOT NULL,
                    orig_id    BIGINT NOT NULL,
                    reason     TEXT   NOT NULL,
                    PRIMARY KEY (table_name, orig_id)
                )
                """.formatted(schema));
            h.execute("""
                CREATE TABLE IF NOT EXISTS "%s".probe_case_collisions (
                    table_name TEXT   NOT NULL,
                    column_name TEXT  NOT NULL,
                    value      TEXT   NOT NULL,
                    row_ids    BIGINT[] NOT NULL,
                    PRIMARY KEY (table_name, column_name, value)
                )
                """.formatted(schema));
            // Safe-parse helper for v4 text columns that are supposed to hold JSON but may
            // not (e.g. NOTIFICATIONRULE.PUBLISHER_CONFIG). Returns NULL on parse failure.
            h.execute("""
                CREATE OR REPLACE FUNCTION "%s".try_jsonb(t text) RETURNS jsonb AS $$
                BEGIN
                    IF t IS NULL THEN
                        RETURN NULL;
                    END IF;
                    RETURN t::jsonb;
                EXCEPTION WHEN OTHERS THEN
                    RETURN NULL;
                END;
                $$ LANGUAGE plpgsql IMMUTABLE
                """.formatted(schema));
        });
    }

    /**
     * Names of all known probe tables. Used by verify and the downstream-invalidation rule.
     */
    public static final java.util.List<String> PROBE_TABLES = java.util.List.of(
        "probe_invalid_uuids",
        "probe_skipped_users",
        "probe_case_collisions"
    );

    public void drop() {
        target.useHandle(h -> h.execute("DROP SCHEMA IF EXISTS \"" + schema + "\" CASCADE"));
    }
}
