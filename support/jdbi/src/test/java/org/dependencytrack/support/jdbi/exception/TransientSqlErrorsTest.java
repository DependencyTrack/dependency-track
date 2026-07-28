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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.sql.SQLException;
import java.sql.SQLRecoverableException;
import java.sql.SQLTransientConnectionException;

import static org.assertj.core.api.Assertions.assertThat;

class TransientSqlErrorsTest {

    @ParameterizedTest
    @ValueSource(strings = {"40001", "40P01", "08000", "08001", "08006", "08007", "53300", "55P03", "57P03"})
    void shouldClassifyTransientSqlStatesAsTransient(String sqlState) {
        assertThat(TransientSqlErrors.isTransient(new SQLException("boom", sqlState))).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"08P01", "23505", "23514", "23502", "42601", "22P02"})
    void shouldClassifyPermanentSqlStatesAsNotTransient(String sqlState) {
        assertThat(TransientSqlErrors.isTransient(new SQLException("boom", sqlState))).isFalse();
    }

    @Test
    void shouldUnwrapCauseChainToFindSqlException() {
        final var wrapped = new RuntimeException("wrapper", new SQLException("boom", "40001"));
        assertThat(TransientSqlErrors.isTransient(wrapped)).isTrue();
    }

    @Test
    void shouldReturnFalseWhenNoSqlExceptionInCauseChain() {
        assertThat(TransientSqlErrors.isTransient(new RuntimeException("no sql here"))).isFalse();
    }

    @Test
    void shouldReturnFalseWhenSqlStateIsAbsent() {
        assertThat(TransientSqlErrors.isTransient(new SQLException("boom"))).isFalse();
    }

    @Test
    void shouldClassifySqlRecoverableExceptionAsTransient() {
        assertThat(TransientSqlErrors.isTransient(
                new SQLRecoverableException("Connection is closed"))).isTrue();
    }

    @Test
    void shouldClassifySqlTransientExceptionAsTransientRegardlessOfSqlState() {
        assertThat(TransientSqlErrors.isTransient(
                new SQLTransientConnectionException(
                        "Connection is not available, request timed out"))).isTrue();
    }

    @Test
    void shouldClassifyTransientSqlStateWrappedInNonTransientSqlException() {
        final var wrapped = new SQLException("wrapper", "23505", new SQLException("boom", "40001"));
        assertThat(TransientSqlErrors.isTransient(wrapped)).isTrue();
    }

}
