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

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.PackageArtifactMetadata;
import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.ColumnMappers;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
@NullMarked
public final class PackageArtifactMetadataRowMapper implements RowMapper<PackageArtifactMetadata> {

    private @Nullable ColumnMapper<Instant> instantColumnMapper;
    private @Nullable ColumnMapper<PackageURL> purlColumnMapper;

    @Override
    public void init(ConfigRegistry registry) {
        final var columnMappers = registry.get(ColumnMappers.class);
        instantColumnMapper = columnMappers.findFor(Instant.class).orElseThrow();
        purlColumnMapper = columnMappers.findFor(PackageURL.class).orElseThrow();
    }

    @Override
    public PackageArtifactMetadata map(ResultSet rs, StatementContext ctx) throws SQLException {
        requireNonNull(instantColumnMapper);
        requireNonNull(purlColumnMapper);

        return new PackageArtifactMetadata(
                purlColumnMapper.map(rs, "PURL", ctx),
                purlColumnMapper.map(rs, "PACKAGE_PURL", ctx),
                rs.getString("HASH_MD5"),
                rs.getString("HASH_SHA1"),
                rs.getString("HASH_SHA256"),
                rs.getString("HASH_SHA512"),
                instantColumnMapper.map(rs, "PUBLISHED_AT", ctx),
                rs.getString("RESOLVED_BY"),
                rs.getString("RESOLVED_FROM"),
                instantColumnMapper.map(rs, "RESOLVED_AT", ctx));
    }

}
