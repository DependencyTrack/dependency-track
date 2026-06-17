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
package org.dependencytrack.dex.engine.persistence.jdbi;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.Parser;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.Nullable;

import java.io.UncheckedIOException;
import java.sql.ResultSet;
import java.sql.SQLException;

final class ProtobufColumnMapper<T extends Message> implements ColumnMapper<T> {

    private final Parser<T> parser;

    public ProtobufColumnMapper(final Parser<T> parser) {
        this.parser = parser;
    }

    @Override
    public @Nullable T map(final ResultSet rs, final int columnNumber, final StatementContext ctx) throws SQLException {
        final byte[] valueBytes = rs.getBytes(columnNumber);
        if (rs.wasNull()) {
            return null;
        }

        try {
            return parser.parseFrom(valueBytes);
        } catch (InvalidProtocolBufferException e) {
            throw new UncheckedIOException("Failed to parse Protobuf message", e);
        }
    }

}