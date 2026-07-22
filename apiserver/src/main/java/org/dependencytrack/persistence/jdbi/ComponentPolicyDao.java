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
package org.dependencytrack.persistence.jdbi;

import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Access to component policies (automated license curation rules).
 */
public final class ComponentPolicyDao {

    private final Handle handle;

    public ComponentPolicyDao(final Handle handle) {
        this.handle = handle;
    }

    public record ComponentPolicy(
            long id,
            String name,
            @Nullable String description,
            @Nullable String author,
            boolean enabled,
            int priority,
            String condition,
            @Nullable Long licenseId,
            @Nullable String details,
            @Nullable Instant validFrom,
            @Nullable Instant validUntil) {
    }

    private static final RowMapper<ComponentPolicy> ROW_MAPPER = (rs, ctx) -> new ComponentPolicy(
            rs.getLong("ID"),
            rs.getString("NAME"),
            rs.getString("DESCRIPTION"),
            rs.getString("AUTHOR"),
            rs.getBoolean("ENABLED"),
            rs.getInt("PRIORITY"),
            rs.getString("CONDITION"),
            rs.getObject("LICENSE_ID", Long.class),
            rs.getString("DETAILS"),
            rs.getTimestamp("VALID_FROM") != null ? rs.getTimestamp("VALID_FROM").toInstant() : null,
            rs.getTimestamp("VALID_UNTIL") != null ? rs.getTimestamp("VALID_UNTIL").toInstant() : null);

    private static final String SELECT = """
            SELECT "ID", "NAME", "DESCRIPTION", "AUTHOR", "ENABLED",
                   "PRIORITY", "CONDITION", "LICENSE_ID", "DETAILS",
                   "VALID_FROM", "VALID_UNTIL"
              FROM "COMPONENT_POLICY"
            """;

    /**
     * All policies, evaluation order: priority ascending, then name.
     */
    public List<ComponentPolicy> getAll() {
        return handle.createQuery(SELECT + " ORDER BY \"PRIORITY\", \"NAME\"")
                .map(ROW_MAPPER)
                .list();
    }

    /**
     * Enabled policies whose validity window (when set) contains now.
     */
    public List<ComponentPolicy> getAllEnabled() {
        return handle.createQuery(SELECT
                        + " WHERE \"ENABLED\""
                        + " AND (\"VALID_FROM\" IS NULL OR \"VALID_FROM\" <= NOW())"
                        + " AND (\"VALID_UNTIL\" IS NULL OR \"VALID_UNTIL\" >= NOW())"
                        + " ORDER BY \"PRIORITY\", \"NAME\"")
                .map(ROW_MAPPER)
                .list();
    }

    public Optional<ComponentPolicy> getById(final long id) {
        return handle.createQuery(SELECT + " WHERE \"ID\" = :id")
                .bind("id", id)
                .map(ROW_MAPPER)
                .findOne();
    }

    public long create(
            final String name,
            @Nullable final String description,
            @Nullable final String author,
            final boolean enabled,
            final int priority,
            final String condition,
            @Nullable final Long licenseId,
            @Nullable final String details,
            @Nullable final Instant validFrom,
            @Nullable final Instant validUntil) {
        return handle.createQuery("""
                        INSERT INTO "COMPONENT_POLICY"
                          ("NAME", "DESCRIPTION", "AUTHOR", "ENABLED",
                           "PRIORITY", "CONDITION", "LICENSE_ID", "DETAILS",
                           "VALID_FROM", "VALID_UNTIL")
                        VALUES
                          (:name, :description, :author, :enabled,
                           :priority, :condition, :licenseId, :details,
                           :validFrom, :validUntil)
                        RETURNING "ID"
                        """)
                .bind("name", name)
                .bind("description", description)
                .bind("author", author)
                .bind("enabled", enabled)
                .bind("priority", priority)
                .bind("condition", condition)
                .bind("licenseId", licenseId)
                .bind("details", details)
                .bind("validFrom", validFrom)
                .bind("validUntil", validUntil)
                .mapTo(Long.class)
                .one();
    }

    public boolean update(
            final long id,
            final String name,
            @Nullable final String description,
            final boolean enabled,
            final int priority,
            final String condition,
            @Nullable final Long licenseId,
            @Nullable final String details,
            @Nullable final Instant validFrom,
            @Nullable final Instant validUntil) {
        return handle.createUpdate("""
                        UPDATE "COMPONENT_POLICY"
                           SET "NAME" = :name
                             , "DESCRIPTION" = :description
                             , "ENABLED" = :enabled
                             , "PRIORITY" = :priority
                             , "CONDITION" = :condition
                             , "LICENSE_ID" = :licenseId
                             , "DETAILS" = :details
                             , "VALID_FROM" = :validFrom
                             , "VALID_UNTIL" = :validUntil
                             , "UPDATED_AT" = NOW()
                         WHERE "ID" = :id
                        """)
                .bind("id", id)
                .bind("name", name)
                .bind("description", description)
                .bind("enabled", enabled)
                .bind("priority", priority)
                .bind("condition", condition)
                .bind("licenseId", licenseId)
                .bind("details", details)
                .bind("validFrom", validFrom)
                .bind("validUntil", validUntil)
                .execute() > 0;
    }

    public boolean delete(final long id) {
        return handle.createUpdate("""
                        DELETE FROM "COMPONENT_POLICY" WHERE "ID" = :id
                        """)
                .bind("id", id)
                .execute() > 0;
    }
}
