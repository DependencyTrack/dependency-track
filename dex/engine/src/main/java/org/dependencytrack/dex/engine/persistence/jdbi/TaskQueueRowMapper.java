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

import org.dependencytrack.dex.engine.api.TaskQueue;
import org.dependencytrack.dex.engine.api.TaskQueueStatus;
import org.dependencytrack.dex.engine.api.TaskType;
import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.ColumnMappers;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;

import static java.util.Objects.requireNonNull;

final class TaskQueueRowMapper implements RowMapper<TaskQueue> {

    private @Nullable ColumnMapper<Instant> instantColumnMapper;

    @Override
    public void init(final ConfigRegistry registry) {
        instantColumnMapper = registry.get(ColumnMappers.class).findFor(Instant.class).orElseThrow();
    }

    @Override
    public TaskQueue map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        requireNonNull(instantColumnMapper);

        return new TaskQueue(
                TaskType.valueOf(rs.getString("type")),
                rs.getString("name"),
                TaskQueueStatus.valueOf(rs.getString("status")),
                rs.getInt("capacity"),
                rs.getInt("depth"),
                instantColumnMapper.map(rs, "created_at", ctx),
                instantColumnMapper.map(rs, "updated_at", ctx));
    }

}
