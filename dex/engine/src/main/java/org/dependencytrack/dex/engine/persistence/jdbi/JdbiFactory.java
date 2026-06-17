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

import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.dex.engine.ActivityTaskId;
import org.dependencytrack.dex.engine.api.TaskQueue;
import org.dependencytrack.dex.engine.api.WorkflowRunHistoryEntry;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.persistence.model.PolledActivityTask;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowEvent;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowTask;
import org.dependencytrack.dex.proto.common.v1.RetryPolicy;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jdbi.v3.freemarker.FreemarkerEngine;
import org.jdbi.v3.jackson2.Jackson2Plugin;
import org.jdbi.v3.postgres.PostgresPlugin;

import javax.sql.DataSource;
import java.time.Duration;
import java.time.Instant;

import static java.util.Objects.requireNonNull;

public final class JdbiFactory {

    private JdbiFactory() {
    }

    public static Jdbi create(
            final DataSource dataSource,
            final PageTokenEncoder pageTokenEncoder) {
        requireNonNull(dataSource, "dataSource must not be null");
        requireNonNull(pageTokenEncoder, "pageTokenEncoder must not be null");

        return Jdbi
                .create(dataSource)
                .installPlugin(new Jackson2Plugin())
                .installPlugin(new PostgresPlugin())
                .setTemplateEngine(FreemarkerEngine.instance())
                .configure(PaginationConfig.class, config -> config.setPageTokenEncoder(pageTokenEncoder))
                .configure(SqlStatements.class, statementsCfg -> statementsCfg.setQueryTimeout(10))
                // Ensure all required mappings are registered *once*
                // on startup. Defining these on a per-query basis imposes
                // additional overhead that is worth avoiding given how
                // frequently queries are being executed.
                .registerArrayType(Duration.class, "interval")
                .registerArrayType(Instant.class, "timestamptz")
                .registerColumnMapper(
                        Payload.class,
                        new ProtobufColumnMapper<>(Payload.parser()))
                .registerColumnMapper(
                        RetryPolicy.class,
                        new ProtobufColumnMapper<>(RetryPolicy.parser()))
                .registerColumnMapper(
                        WorkflowEvent.class,
                        new ProtobufColumnMapper<>(WorkflowEvent.parser()))
                .registerRowMapper(
                        ActivityTaskId.class,
                        new ActivityTaskIdRowMapper())
                .registerRowMapper(
                        PolledActivityTask.class,
                        new PolledActivityTaskRowMapper())
                .registerRowMapper(
                        PolledWorkflowEvent.class,
                        new PolledWorkflowEventRowMapper())
                .registerRowMapper(
                        PolledWorkflowTask.class,
                        new PolledWorkflowRunRowMapper())
                .registerRowMapper(
                        TaskQueue.class,
                        new TaskQueueRowMapper())
                .registerRowMapper(
                        WorkflowRunHistoryEntry.class,
                        new WorkflowRunHistoryEntryRowMapper())
                .registerRowMapper(
                        WorkflowRunMetadata.class,
                        new WorkflowRunMetadataRowMapper());
    }

}
