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
package org.dependencytrack.policy.cel.persistence;

import org.dependencytrack.persistence.jdbi.mapping.OptionalColumnRowMapper;
import org.dependencytrack.proto.policy.v1.HealthMeta;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.nullableTimestamp;

public final class CelPolicyHealthRowMapper implements OptionalColumnRowMapper<HealthMeta> {

    @Override
    public HealthMeta map(ResultSet rs, StatementContext ctx, Columns columns) throws SQLException {
        return mapToBuilder(rs, columns).build();
    }

    HealthMeta.Builder mapToBuilder(ResultSet rs, Columns columns) throws SQLException {
        final HealthMeta.Builder builder = HealthMeta.newBuilder();
        columns.maybeSet(rs, "scorecard_score", CelPolicyHealthRowMapper::nullableFloat, builder::setScorecardScore);
        columns.maybeSet(
                rs, "avg_issue_age_days", CelPolicyHealthRowMapper::nullableFloat, builder::setAvgIssueAgeDays);
        columns.maybeSet(
                rs,
                "commit_frequency_weekly",
                CelPolicyHealthRowMapper::nullableFloat,
                builder::setCommitFrequencyWeekly);
        columns.maybeSet(
                rs,
                "last_commit",
                (resultSet, columnName) -> nullableTimestamp(resultSet, columnName),
                builder::setLastCommit);
        columns.maybeSet(rs, "dependents", CelPolicyHealthRowMapper::nullableLong, builder::setDependents);
        columns.maybeSet(rs, "bus_factor", CelPolicyHealthRowMapper::nullableInt, builder::setBusFactor);
        columns.maybeSet(rs, "stars", CelPolicyHealthRowMapper::nullableLong, builder::setStars);
        columns.maybeSet(rs, "forks", CelPolicyHealthRowMapper::nullableLong, builder::setForks);
        columns.maybeSet(rs, "is_repo_archived", CelPolicyHealthRowMapper::nullableBoolean, builder::setIsRepoArchived);
        return builder;
    }

    private static @Nullable Float nullableFloat(ResultSet rs, String columnName) throws SQLException {
        final float value = rs.getFloat(columnName);
        return rs.wasNull() ? null : value;
    }

    private static @Nullable Long nullableLong(ResultSet rs, String columnName) throws SQLException {
        final long value = rs.getLong(columnName);
        return rs.wasNull() ? null : value;
    }

    private static @Nullable Integer nullableInt(ResultSet rs, String columnName) throws SQLException {
        final int value = rs.getInt(columnName);
        return rs.wasNull() ? null : value;
    }

    private static @Nullable Boolean nullableBoolean(ResultSet rs, String columnName) throws SQLException {
        final boolean value = rs.getBoolean(columnName);
        return rs.wasNull() ? null : value;
    }
}
