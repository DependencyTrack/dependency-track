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

import org.dependencytrack.notification.proto.v1.Bom;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class NotificationBomRowMapper implements RowMapper<Bom> {

    @Override
    public Bom map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final Bom.Builder builder = Bom.newBuilder();
        maybeSet(rs, "bomFormat", ResultSet::getString, builder::setFormat);
        maybeSet(rs, "bomSpecVersion", ResultSet::getString, builder::setSpecVersion);
        maybeSet(rs, "bomContent", ResultSet::getString, builder::setContent);
        return builder.build();
    }

}
