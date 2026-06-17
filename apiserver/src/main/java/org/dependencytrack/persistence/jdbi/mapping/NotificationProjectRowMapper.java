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

import org.dependencytrack.notification.proto.v1.Project;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class NotificationProjectRowMapper implements RowMapper<Project> {

    @Override
    public Project map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final Project.Builder builder = Project.newBuilder();
        maybeSet(rs, "projectUuid", ResultSet::getString, builder::setUuid);
        maybeSet(rs, "projectName", ResultSet::getString, builder::setName);
        maybeSet(rs, "projectVersion", ResultSet::getString, builder::setVersion);
        maybeSet(rs, "projectDescription", ResultSet::getString, builder::setDescription);
        maybeSet(rs, "projectPurl", ResultSet::getString, builder::setPurl);
        maybeSet(rs, "projectTags", RowMapperUtil::stringArray, builder::addAllTags);
        maybeSet(rs, "isActive", ResultSet::getBoolean, builder::setIsActive);
        return builder.build();
    }

}
