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

import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;

/// @since 5.2.0
@FunctionalInterface
public interface OptionalColumnRowMapper<T> extends RowMapper<T> {

    @Override
    default T map(ResultSet rs, StatementContext ctx) throws SQLException {
        return map(rs, ctx, Columns.of(rs));
    }

    @Override
    default RowMapper<T> specialize(ResultSet rs, StatementContext ctx) throws SQLException {
        final var columns = Columns.of(rs);
        return (r, c) -> map(r, c, columns);
    }

    T map(ResultSet rs, StatementContext ctx, Columns columns) throws SQLException;

    final class Columns {

        private final Set<String> labels;

        private Columns(Set<String> labels) {
            this.labels = labels;
        }

        public static Columns of(ResultSet rs) throws SQLException {
            final ResultSetMetaData metaData = rs.getMetaData();
            final var labels = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            for (int i = 1; i <= metaData.getColumnCount(); i++) {
                labels.add(metaData.getColumnLabel(i));
            }

            return new Columns(labels);
        }

        public boolean contains(String label) {
            return labels.contains(label);
        }

        /// Invokes `getter` if the column `label` is present, and calls `setter` with its result, if not `null`.
        ///
        /// This is desirable when mapping to Protobuf objects, as Protobuf differentiates between
        /// fields that are "empty" or not set at all. Because Protobuf does not support `null`, the
        /// only way to achieve the desired outcome is to not call a setter at all if the value is `null`.
        public <V> void maybeSet(ResultSet rs, String label, Getter<V> getter, Consumer<V> setter) throws SQLException {
            if (!labels.contains(label)) {
                return;
            }

            final V value = getter.get(rs, label);
            if (value != null) {
                setter.accept(value);
            }
        }
    }

    @FunctionalInterface
    interface Getter<V> {

        @Nullable
        V get(ResultSet rs, String label) throws SQLException;
    }
}
