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
package org.dependencytrack.dex.engine.persistence.jdbi;

import org.dependencytrack.dex.engine.persistence.model.PolledActivityTask;
import org.dependencytrack.dex.proto.common.v1.RetryPolicy;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.ColumnMappers;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

final class PolledActivityTaskRowMapper implements RowMapper<PolledActivityTask> {

    private @Nullable ColumnMapper<Instant> instantColumnMapper;
    private @Nullable ColumnMapper<Payload> payloadColumnMapper;
    private @Nullable ColumnMapper<RetryPolicy> retryPolicyColumnMapper;

    @Override
    public void init(final ConfigRegistry registry) {
        final var columnMappers = registry.get(ColumnMappers.class);
        instantColumnMapper = columnMappers.findFor(Instant.class).orElseThrow();
        payloadColumnMapper = columnMappers.findFor(Payload.class).orElseThrow();
        retryPolicyColumnMapper = columnMappers.findFor(RetryPolicy.class).orElseThrow();
    }

    @Override
    public PolledActivityTask map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        requireNonNull(instantColumnMapper);
        requireNonNull(payloadColumnMapper);
        requireNonNull(retryPolicyColumnMapper);

        return new PolledActivityTask(
                rs.getObject("workflow_run_id", UUID.class),
                rs.getInt("created_event_id"),
                rs.getString("activity_name"),
                rs.getString("queue_name"),
                rs.getInt("priority"),
                payloadColumnMapper.map(rs, "argument", ctx),
                retryPolicyColumnMapper.map(rs, "retry_policy", ctx),
                rs.getInt("attempt"),
                instantColumnMapper.map(rs, "locked_until", ctx),
                rs.getInt("lock_version"));
    }

}
