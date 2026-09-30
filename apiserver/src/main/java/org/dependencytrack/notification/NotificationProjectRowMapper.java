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
package org.dependencytrack.notification;

import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.persistence.jdbi.mapping.OptionalColumnRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

public final class NotificationProjectRowMapper implements OptionalColumnRowMapper<Project> {

    @Override
    public Project map(ResultSet rs, StatementContext ctx, Columns columns) throws SQLException {
        final var builder = Project.newBuilder();
        columns.maybeSet(rs, "projectUuid", ResultSet::getString, builder::setUuid);
        columns.maybeSet(rs, "projectName", ResultSet::getString, builder::setName);
        columns.maybeSet(rs, "projectVersion", ResultSet::getString, builder::setVersion);
        columns.maybeSet(rs, "projectDescription", ResultSet::getString, builder::setDescription);
        columns.maybeSet(rs, "projectPurl", ResultSet::getString, builder::setPurl);
        columns.maybeSet(rs, "projectTags", RowMapperUtil::stringArray, builder::addAllTags);
        columns.maybeSet(rs, "isActive", ResultSet::getBoolean, builder::setIsActive);
        return builder.build();
    }
}
