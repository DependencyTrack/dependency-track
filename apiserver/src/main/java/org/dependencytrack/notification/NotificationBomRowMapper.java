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

import org.dependencytrack.notification.proto.v1.Bom;
import org.dependencytrack.persistence.jdbi.mapping.OptionalColumnRowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

public final class NotificationBomRowMapper implements OptionalColumnRowMapper<Bom> {

    @Override
    public Bom map(ResultSet rs, StatementContext ctx, Columns columns) throws SQLException {
        final var builder = Bom.newBuilder();
        columns.maybeSet(rs, "bomFormat", ResultSet::getString, builder::setFormat);
        columns.maybeSet(rs, "bomSpecVersion", ResultSet::getString, builder::setSpecVersion);
        columns.maybeSet(rs, "bomContent", ResultSet::getString, builder::setContent);
        return builder.build();
    }
}
