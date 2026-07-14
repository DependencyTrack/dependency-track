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
package org.dependencytrack.support.jdbi.exception;

import org.jspecify.annotations.Nullable;
import org.postgresql.util.PSQLException;
import org.postgresql.util.ServerErrorMessage;

/**
 * @since 5.0.0
 */
public sealed class ConstraintViolationException extends RuntimeException
        permits UniqueConstraintViolationException,
        CheckConstraintViolationException,
        NotNullConstraintViolationException {

    private final @Nullable String constraintName;
    private final @Nullable String tableName;
    private final @Nullable String columnName;
    private final String sqlState;

    protected ConstraintViolationException(
            @Nullable String message,
            @Nullable Throwable cause,
            @Nullable String constraintName,
            @Nullable String tableName,
            @Nullable String columnName,
            String sqlState) {
        super(message, cause);
        this.constraintName = constraintName;
        this.tableName = tableName;
        this.columnName = columnName;
        this.sqlState = sqlState;
    }

    public static @Nullable ConstraintViolationException of(Throwable throwable) {
        final PSQLException psqlException = findPSQLException(throwable);
        if (psqlException == null) {
            return null;
        }

        final String sqlState = psqlException.getSQLState();
        if (sqlState == null) {
            return null;
        }

        final ServerErrorMessage serverError = psqlException.getServerErrorMessage();
        final String constraintName = serverError != null
                ? serverError.getConstraint()
                : null;
        final String tableName = serverError != null
                ? serverError.getTable()
                : null;
        final String columnName = serverError != null
                ? serverError.getColumn()
                : null;
        final String message = psqlException.getMessage();

        return switch (sqlState) {
            case "23505" -> new UniqueConstraintViolationException(
                    message, throwable, constraintName, tableName, columnName, sqlState);
            case "23514" -> new CheckConstraintViolationException(
                    message, throwable, constraintName, tableName, columnName, sqlState);
            case "23502" -> new NotNullConstraintViolationException(
                    message, throwable, constraintName, tableName, columnName, sqlState);
            default -> null;
        };
    }

    public @Nullable String getConstraintName() {
        return constraintName;
    }

    public @Nullable String getTableName() {
        return tableName;
    }

    public @Nullable String getColumnName() {
        return columnName;
    }

    public String getSqlState() {
        return sqlState;
    }

    private static @Nullable PSQLException findPSQLException(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (current instanceof PSQLException psql) {
                return psql;
            }
            current = current.getCause();
        }
        return null;
    }

}