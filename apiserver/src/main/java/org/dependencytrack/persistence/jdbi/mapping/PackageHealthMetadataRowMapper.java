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
import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.model.PackageHealthScorecardCheck;
import org.dependencytrack.support.jdbi.mapping.PurlColumnMapper;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Maps rows from {@code PACKAGE_HEALTH_METADATA} to
 * {@link PackageHealthMetadata}, together with their previously loaded scorecard checks.
 *
 * @since 5.2.0
 */
@NullMarked
public final class PackageHealthMetadataRowMapper implements RowMapper<PackageHealthMetadata> {

    // Not registered globally, see JdbiFactory. Health rows only hold PURLs written by package
    // metadata resolution, so they always parse.
    private final PurlColumnMapper purlColumnMapper = new PurlColumnMapper();
    private final Map<String, List<PackageHealthScorecardCheck>> checksByPurl;

    /**
     * @param checksByPurl Scorecard checks by canonical package PURL
     */
    public PackageHealthMetadataRowMapper(final Map<String, List<PackageHealthScorecardCheck>> checksByPurl) {
        this.checksByPurl = checksByPurl;
    }

    @Override
    public PackageHealthMetadata map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final PackageURL purl = purlColumnMapper.map(rs, "PURL", ctx);

        return new PackageHealthMetadata(
                purl,
                rs.getObject("STARS", Long.class),
                rs.getObject("FORKS", Long.class),
                rs.getObject("CONTRIBUTORS", Long.class),
                rs.getObject("COMMIT_FREQUENCY_WEEKLY", Float.class),
                rs.getObject("OPEN_ISSUES", Long.class),
                rs.getObject("OPEN_PRS", Long.class),
                getInstant(rs, "LAST_COMMIT"),
                rs.getObject("BUS_FACTOR", Integer.class),
                rs.getObject("HAS_README", Boolean.class),
                rs.getObject("HAS_CODE_OF_CONDUCT", Boolean.class),
                rs.getObject("HAS_SECURITY_POLICY", Boolean.class),
                rs.getObject("DEPENDENTS", Long.class),
                rs.getObject("FILES", Long.class),
                rs.getObject("IS_REPO_ARCHIVED", Boolean.class),
                rs.getObject("SCORECARD_SCORE", Float.class),
                rs.getString("SCORECARD_REF_VERSION"),
                getInstant(rs, "SCORECARD_TIMESTAMP"),
                getInstant(rs, "PROJECT_METADATA_OBSERVED_AT"),
                rs.getString("DEPS_DEV_URL"),
                rs.getString("GITHUB_URL"),
                rs.getObject("AVG_ISSUE_AGE_DAYS", Float.class),
                getInstant(rs, "LAST_FETCH"),
                PackageHealthMetadataStatus.valueOf(rs.getString("STATUS")),
                checksByPurl.getOrDefault(purl.canonicalize(), List.of()));
    }

    private static @Nullable Instant getInstant(final ResultSet rs, final String columnName) throws SQLException {

        final Timestamp timestamp = rs.getTimestamp(columnName);
        return timestamp != null ? timestamp.toInstant() : null;
    }
}
