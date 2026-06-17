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

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.common.Mappers;
import org.jdbi.v3.core.result.UnableToProduceResultException;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.function.Consumer;

import static org.apache.commons.lang3.StringUtils.isBlank;

public class RowMapperUtil {

    private RowMapperUtil() {
    }

    public interface ThrowingBiFunction<V> {
        V apply(final ResultSet rs, final String key) throws SQLException;
    }

    /**
     * Invokes {@code getter} if a column with name {@code columnName} is present in a given {@link ResultSet},
     * and calls {@code setter} with the value returned by {@code getter}, if it is not {@code null}.
     * <p>
     * This behavior is desirable when mapping to Protobuf objects, as Protobuf differentiates between
     * fields that are "empty" or not set at all. Because Protobuf does not support {@code null}, the
     * only way to achieve the desired outcome is to not call a setter at all if the value is {@code null}.
     *
     * @param rs         The {@link ResultSet} to operate on
     * @param columnName Name of the column to operate on
     * @param getter     The {@link ThrowingBiFunction} to call when the column exists
     * @param setter     The {@link Consumer} to call when {@code getter} returns a non-{@code null} value
     * @param <V>        The value type
     * @throws SQLException When accessing the {@link ResultSet} failed
     */
    public static <V> void maybeSet(final ResultSet rs, final String columnName, final ThrowingBiFunction<V> getter, final Consumer<V> setter) throws SQLException {
        final V value = maybeGet(rs, columnName, getter);
        if (value != null) {
            setter.accept(value);
        }
    }

    public static <V> V maybeGet(final ResultSet rs, final String columnName, final ThrowingBiFunction<V> getter) throws SQLException {
        if (!hasColumn(rs, columnName)) {
            return null;
        }
        return getter.apply(rs, columnName);
    }

    public static boolean hasColumn(final ResultSet rs, final String columnName) throws SQLException {
        try {
            return rs.findColumn(columnName) >= 0;
        } catch (SQLException e) {
            if (e instanceof final PSQLException pe) {
                if (PSQLState.UNDEFINED_COLUMN.getState().equals(pe.getSQLState())) {
                    return false;
                }
            }

            throw e;
        }
    }

    public static Double nullableDouble(final ResultSet rs, final String columnName) throws SQLException {
        final double value = rs.getDouble(columnName);
        if (rs.wasNull()) {
            return null;
        }

        return value;
    }

    public static Timestamp nullableTimestamp(final ResultSet rs, final String columnName) throws SQLException {
        final Date timestamp = rs.getTimestamp(columnName);
        return timestamp != null ? Timestamps.fromDate(timestamp) : null;
    }

    public static List<String> stringArray(final ResultSet rs, final String columnName) throws SQLException {
        final Array array = rs.getArray(columnName);
        if (array == null) {
            return Collections.emptyList();
        }
        if (array.getBaseType() != Types.VARCHAR) {
            throw new IllegalArgumentException("Expected array with base type VARCHAR, but got %s".formatted(array.getBaseTypeName()));
        }

        return Arrays.asList((String[]) array.getArray());
    }

    public static List<Long> longArray(final ResultSet rs, final String columnName) throws SQLException {
        final Array array = rs.getArray(columnName);
        if (array == null) {
            return Collections.emptyList();
        }
        if (array.getBaseType() != Types.BIGINT) {
            throw new IllegalArgumentException("Expected array with base type BIGINT, but got %s".formatted(array.getBaseTypeName()));
        }
        return Arrays.asList((Long[]) array.getArray());
    }

    public static <T> T deserializeJson(final ResultSet rs, final String columnName, final TypeReference<T> typeReference) throws SQLException {
        final String jsonString = rs.getString(columnName);
        if (isBlank(jsonString)) {
            return null;
        }

        try {
            return Mappers.jsonMapper().readValue(jsonString, typeReference);
        } catch (JacksonException e) {
            throw new UnableToProduceResultException(e);
        }
    }

}
