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

import org.jdbi.v3.core.statement.UnableToExecuteStatementException;
import org.junit.jupiter.api.Test;
import org.postgresql.util.PSQLException;
import org.postgresql.util.ServerErrorMessage;

import java.lang.reflect.Constructor;

import static org.assertj.core.api.Assertions.assertThat;

class ConstraintViolationExceptionTest {

    @Test
    void shouldTranslateUniqueViolation() {
        final var psqlException = createPSQLException(
                "23505", "VULNERABILITY_POLICY_NAME_IDX", "VULNERABILITY_POLICY", null);
        final var wrapping = new UnableToExecuteStatementException(psqlException, null);

        final var result = ConstraintViolationException.of(wrapping);

        assertThat(result).isInstanceOf(UniqueConstraintViolationException.class);
        assertThat(result.getConstraintName()).isEqualTo("VULNERABILITY_POLICY_NAME_IDX");
        assertThat(result.getTableName()).isEqualTo("VULNERABILITY_POLICY");
        assertThat(result.getColumnName()).isNull();
        assertThat(result.getSqlState()).isEqualTo("23505");
        assertThat(result.getCause()).isSameAs(wrapping);
    }

    @Test
    void shouldTranslateCheckViolation() {
        final var psqlException = createPSQLException(
                "23514", "VULNERABILITY_POLICY_PRIORITY_check", "VULNERABILITY_POLICY", null);
        final var wrapping = new UnableToExecuteStatementException(psqlException, null);

        final var result = ConstraintViolationException.of(wrapping);

        assertThat(result).isInstanceOf(CheckConstraintViolationException.class);
        assertThat(result.getConstraintName()).isEqualTo("VULNERABILITY_POLICY_PRIORITY_check");
        assertThat(result.getTableName()).isEqualTo("VULNERABILITY_POLICY");
        assertThat(result.getSqlState()).isEqualTo("23514");
    }

    @Test
    void shouldTranslateNotNullViolation() {
        final var psqlException = createPSQLException(
                "23502", null, "VULNERABILITY_POLICY", "NAME");
        final var wrapping = new UnableToExecuteStatementException(psqlException, null);

        final var result = ConstraintViolationException.of(wrapping);

        assertThat(result).isInstanceOf(NotNullConstraintViolationException.class);
        assertThat(result.getConstraintName()).isNull();
        assertThat(result.getTableName()).isEqualTo("VULNERABILITY_POLICY");
        assertThat(result.getColumnName()).isEqualTo("NAME");
        assertThat(result.getSqlState()).isEqualTo("23502");
    }

    @Test
    void shouldReturnNullForForeignKeyViolation() {
        final var psqlException = createPSQLException("23503", "some_fk", "SOME_TABLE", null);
        final var wrapping = new UnableToExecuteStatementException(psqlException, null);

        assertThat(ConstraintViolationException.of(wrapping)).isNull();
    }

    @Test
    void shouldReturnNullForNonPSQLException() {
        final var wrapping = new UnableToExecuteStatementException(
                new RuntimeException("not a psql error"), null);

        assertThat(ConstraintViolationException.of(wrapping)).isNull();
    }

    @Test
    void shouldReturnNullForNullSqlState() {
        final var psqlException = new PSQLException("error", null);
        final var wrapping = new UnableToExecuteStatementException(psqlException, null);

        assertThat(ConstraintViolationException.of(wrapping)).isNull();
    }

    @Test
    void shouldFindPSQLExceptionInDeepCauseChain() {
        final var psqlException = createPSQLException(
                "23505", "some_idx", "SOME_TABLE", null);
        final var mid = new RuntimeException("mid", psqlException);
        final var outer = new UnableToExecuteStatementException(mid, null);

        final var result = ConstraintViolationException.of(outer);

        assertThat(result).isInstanceOf(UniqueConstraintViolationException.class);
        assertThat(result.getConstraintName()).isEqualTo("some_idx");
    }

    @Test
    void shouldPreserveOriginalExceptionAsCause() {
        final var psqlException = createPSQLException(
                "23505", "some_idx", "SOME_TABLE", null);
        final var wrapping = new UnableToExecuteStatementException(psqlException, null);

        final var result = ConstraintViolationException.of(wrapping);

        assertThat(result).isNotNull();
        assertThat(result.getCause()).isSameAs(wrapping);
    }

    private static PSQLException createPSQLException(
            String sqlState,
            String constraintName,
            String tableName,
            String columnName) {
        try {
            final String encodedMessage = buildEncodedServerErrorMessage(
                    sqlState, constraintName, tableName, columnName);
            final Constructor<ServerErrorMessage> constructor =
                    ServerErrorMessage.class.getDeclaredConstructor(String.class);
            constructor.setAccessible(true);
            final ServerErrorMessage serverErrorMessage = constructor.newInstance(encodedMessage);
            return new PSQLException(serverErrorMessage);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to create PSQLException for test", e);
        }
    }

    /**
     * @see <a href="https://www.postgresql.org/docs/current/protocol-error-fields.html">Protocol Error Fields</a>
     */
    private static String buildEncodedServerErrorMessage(
            String sqlState,
            String constraintName,
            String tableName,
            String columnName) {
        final var sb = new StringBuilder();
        sb.append('S').append("ERROR").append('\0');
        sb.append('C').append(sqlState).append('\0');
        sb.append('M').append("test error message").append('\0');
        if (tableName != null) {
            sb.append('t').append(tableName).append('\0');
        }
        if (columnName != null) {
            sb.append('c').append(columnName).append('\0');
        }
        if (constraintName != null) {
            sb.append('n').append(constraintName).append('\0');
        }
        sb.append('\0');
        return sb.toString();
    }

}
