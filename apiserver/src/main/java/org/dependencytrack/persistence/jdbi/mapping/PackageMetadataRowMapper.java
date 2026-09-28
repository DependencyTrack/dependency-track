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
package org.dependencytrack.persistence.jdbi.mapping;

import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.support.jdbi.mapping.PurlColumnMapper;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.NullMarked;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * @since 5.0.0
 */
@NullMarked
public final class PackageMetadataRowMapper implements RowMapper<PackageMetadata> {

    private final PurlColumnMapper purlColumnMapper = new PurlColumnMapper();

    @Override
    public PackageMetadata map(ResultSet rs, StatementContext ctx) throws SQLException {
        final var latestVersionPublishedAt = rs.getTimestamp("LATEST_VERSION_PUBLISHED_AT");

        return new PackageMetadata(
                purlColumnMapper.map(rs, "PURL", ctx),
                rs.getString("LATEST_VERSION"),
                latestVersionPublishedAt != null ? latestVersionPublishedAt.toInstant() : null,
                rs.getTimestamp("RESOLVED_AT").toInstant(),
                rs.getString("RESOLVED_FROM"),
                rs.getString("RESOLVED_BY"));
    }
}
