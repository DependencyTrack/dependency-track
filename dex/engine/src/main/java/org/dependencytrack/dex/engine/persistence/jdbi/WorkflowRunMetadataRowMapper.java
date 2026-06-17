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

import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.ColumnMappers;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper.TypedJsonMapper;
import org.jspecify.annotations.Nullable;

import java.lang.reflect.Type;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.jdbi.v3.core.generic.GenericTypes.parameterizeClass;

final class WorkflowRunMetadataRowMapper implements RowMapper<WorkflowRunMetadata> {

    private static final Type LABELS_TYPE = parameterizeClass(Map.class, String.class, String.class);

    private @Nullable ColumnMapper<Instant> instantColumnMapper;
    private @Nullable TypedJsonMapper labelsJsonMapper;

    @Override
    public void init(final ConfigRegistry registry) {
        instantColumnMapper = registry.get(ColumnMappers.class).findFor(Instant.class).orElseThrow();
        labelsJsonMapper = registry.get(JsonConfig.class).getJsonMapper().forType(LABELS_TYPE, registry);
    }

    @Override
    public WorkflowRunMetadata map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        requireNonNull(instantColumnMapper);

        return new WorkflowRunMetadata(
                rs.getObject("id", UUID.class),
                rs.getObject("parent_id", UUID.class),
                rs.getString("workflow_name"),
                rs.getInt("workflow_version"),
                rs.getString("workflow_instance_id"),
                rs.getString("task_queue_name"),
                WorkflowRunStatus.valueOf(rs.getString("status")),
                rs.getString("custom_status"),
                rs.getInt("priority"),
                rs.getString("concurrency_key"),
                getLabels(rs, ctx),
                instantColumnMapper.map(rs, "created_at", ctx),
                instantColumnMapper.map(rs, "updated_at", ctx),
                instantColumnMapper.map(rs, "started_at", ctx),
                instantColumnMapper.map(rs, "completed_at", ctx));
    }

    @SuppressWarnings("unchecked")
    private @Nullable Map<String, String> getLabels(final ResultSet rs, final StatementContext ctx) throws SQLException {
        requireNonNull(labelsJsonMapper);

        final String labelsJson = rs.getString("labels");
        if (rs.wasNull()) {
            return null;
        }

        return (Map<String, String>) labelsJsonMapper.fromJson(labelsJson, ctx.getConfig());
    }

}
