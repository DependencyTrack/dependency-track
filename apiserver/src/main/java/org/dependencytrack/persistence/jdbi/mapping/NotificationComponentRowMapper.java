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

import org.dependencytrack.notification.proto.v1.Component;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class NotificationComponentRowMapper implements RowMapper<Component> {

    @Override
    public Component map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final Component.Builder builder = Component.newBuilder();
        maybeSet(rs, "componentUuid", ResultSet::getString, builder::setUuid);
        maybeSet(rs, "componentGroup", ResultSet::getString, builder::setGroup);
        maybeSet(rs, "componentName", ResultSet::getString, builder::setName);
        maybeSet(rs, "componentVersion", ResultSet::getString, builder::setVersion);
        maybeSet(rs, "componentPurl", ResultSet::getString, builder::setPurl);
        maybeSet(rs, "componentMd5", ResultSet::getString, builder::setMd5);
        maybeSet(rs, "componentSha1", ResultSet::getString, builder::setSha1);
        maybeSet(rs, "componentSha256", ResultSet::getString, builder::setSha256);
        maybeSet(rs, "componentSha512", ResultSet::getString, builder::setSha512);
        return builder.build();
    }

}
