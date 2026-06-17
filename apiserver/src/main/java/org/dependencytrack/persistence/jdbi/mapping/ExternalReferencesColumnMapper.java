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

import org.apache.commons.lang3.SerializationUtils;
import org.dependencytrack.model.ExternalReference;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

@NullMarked
public final class ExternalReferencesColumnMapper implements ColumnMapper<List<ExternalReference>> {

    @Override
    public @Nullable List<ExternalReference> map(ResultSet r, int columnNumber, StatementContext ctx) throws SQLException {
        if (r.getBytes(columnNumber) == null) {
            return null;
        }

        return SerializationUtils.deserialize(r.getBytes(columnNumber));
    }

}
