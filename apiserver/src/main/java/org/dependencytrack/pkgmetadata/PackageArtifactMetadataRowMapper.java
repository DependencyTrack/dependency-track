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
package org.dependencytrack.pkgmetadata;

import com.github.packageurl.PackageURL;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;

/**
 * @since 5.0.0
 */
public final class PackageArtifactMetadataRowMapper implements RowMapper<PackageArtifactMetadata> {

    @Override
    public RowMapper<PackageArtifactMetadata> specialize(ResultSet rs, StatementContext ctx) {
        final ColumnMapper<PackageURL> purlColumnMapper =
                ctx.findColumnMapperFor(PackageURL.class).orElseThrow();
        final ColumnMapper<Instant> instantColumnMapper =
                ctx.findColumnMapperFor(Instant.class).orElseThrow();

        return (r, c) -> new PackageArtifactMetadata(
                purlColumnMapper.map(r, "PURL", c),
                purlColumnMapper.map(r, "PACKAGE_PURL", c),
                r.getString("HASH_MD5"),
                r.getString("HASH_SHA1"),
                r.getString("HASH_SHA256"),
                r.getString("HASH_SHA512"),
                instantColumnMapper.map(r, "PUBLISHED_AT", c),
                r.getString("RESOLVED_BY"),
                r.getString("RESOLVED_FROM"),
                instantColumnMapper.map(r, "RESOLVED_AT", c));
    }

    @Override
    public PackageArtifactMetadata map(ResultSet rs, StatementContext ctx) throws SQLException {
        return specialize(rs, ctx).map(rs, ctx);
    }
}
