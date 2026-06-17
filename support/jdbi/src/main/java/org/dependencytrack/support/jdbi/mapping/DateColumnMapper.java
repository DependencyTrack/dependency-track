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
package org.dependencytrack.support.jdbi.mapping;

import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.ColumnMappers;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Date;

import static java.util.Objects.requireNonNull;

/// @since 5.0.0
public final class DateColumnMapper implements ColumnMapper<Date> {

    private @Nullable ColumnMapper<@Nullable Instant> instantColumnMapper;

    @Override
    public void init(ConfigRegistry registry) {
        instantColumnMapper = registry.get(ColumnMappers.class).findFor(Instant.class).orElseThrow();
    }

    @Override
    public @Nullable Date map(ResultSet rs, int columnNumber, StatementContext ctx) throws SQLException {
        requireNonNull(instantColumnMapper, "instantColumnMapper must not be null");
        final Instant instant = instantColumnMapper.map(rs, columnNumber, ctx);
        if (instant == null) {
            return null;
        }

        return Date.from(instant);
    }

}
