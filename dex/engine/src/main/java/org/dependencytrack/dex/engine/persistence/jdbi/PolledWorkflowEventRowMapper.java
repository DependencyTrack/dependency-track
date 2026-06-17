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

import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowEvent;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.ColumnMappers;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

final class PolledWorkflowEventRowMapper implements RowMapper<PolledWorkflowEvent> {

    private @Nullable ColumnMapper<WorkflowEvent> eventColumnMapper;

    @Override
    public void init(final ConfigRegistry registry) {
        eventColumnMapper = registry.get(ColumnMappers.class).findFor(WorkflowEvent.class).orElseThrow();
    }

    @Override
    public PolledWorkflowEvent map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        requireNonNull(eventColumnMapper);

        return new PolledWorkflowEvent(
                PolledWorkflowEvent.EventType.valueOf(rs.getString("event_type")),
                rs.getObject("workflow_run_id", UUID.class),
                eventColumnMapper.map(rs, "event", ctx),
                rs.getInt("sequence_number"),
                rs.getInt("message_id"));
    }

}
