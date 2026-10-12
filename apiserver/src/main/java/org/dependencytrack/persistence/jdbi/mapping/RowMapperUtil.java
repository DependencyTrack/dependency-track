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
import org.jspecify.annotations.Nullable;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.apache.commons.lang3.StringUtils.isBlank;

public final class RowMapperUtil {

    private RowMapperUtil() {}

    public static @Nullable Double nullableDouble(ResultSet rs, String columnName) throws SQLException {
        final double value = rs.getDouble(columnName);
        if (rs.wasNull()) {
            return null;
        }

        return value;
    }

    public static @Nullable Timestamp nullableTimestamp(ResultSet rs, String columnName) throws SQLException {
        final Date timestamp = rs.getTimestamp(columnName);
        return timestamp != null ? Timestamps.fromDate(timestamp) : null;
    }

    public static List<String> stringArray(ResultSet rs, String columnName) throws SQLException {
        final Array array = rs.getArray(columnName);
        if (array == null) {
            return Collections.emptyList();
        }
        if (array.getBaseType() != Types.VARCHAR) {
            throw new IllegalArgumentException(
                    "Expected array with base type VARCHAR, but got %s".formatted(array.getBaseTypeName()));
        }

        return Arrays.asList((String[]) array.getArray());
    }

    public static List<Long> longArray(ResultSet rs, String columnName) throws SQLException {
        final Array array = rs.getArray(columnName);
        if (array == null) {
            return Collections.emptyList();
        }
        if (array.getBaseType() != Types.BIGINT) {
            throw new IllegalArgumentException(
                    "Expected array with base type BIGINT, but got %s".formatted(array.getBaseTypeName()));
        }

        return Arrays.asList((Long[]) array.getArray());
    }

    public static <T> @Nullable T deserializeJson(ResultSet rs, String columnName, TypeReference<T> typeReference)
            throws SQLException {
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
