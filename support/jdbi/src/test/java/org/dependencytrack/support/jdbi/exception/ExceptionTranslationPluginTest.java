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

import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@Testcontainers
class ExceptionTranslationPluginTest {

    @Container
    private static final PostgreSQLContainer POSTGRES =
            new PostgreSQLContainer("postgres:14-alpine");

    private static Jdbi jdbi;

    @BeforeAll
    static void beforeAll() {
        jdbi = Jdbi
                .create(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .installPlugin(new ExceptionTranslationPlugin());

        jdbi.useHandle(handle -> handle.execute("""
                CREATE TABLE "TEST_TABLE" (
                    "ID" SERIAL PRIMARY KEY,
                    "NAME" TEXT NOT NULL,
                    "STATUS" TEXT NOT NULL CHECK ("STATUS" IN ('ACTIVE', 'INACTIVE')),
                    UNIQUE ("NAME")
                )"""));
    }

    @Test
    void shouldTranslateUniqueConstraintViolation() {
        jdbi.useHandle(handle -> handle.execute("""
                INSERT INTO "TEST_TABLE" ("NAME", "STATUS") VALUES ('foo', 'ACTIVE')"""));

        assertThatExceptionOfType(UniqueConstraintViolationException.class)
                .isThrownBy(() -> jdbi.useHandle(handle -> handle.execute("""
                        INSERT INTO "TEST_TABLE" ("NAME", "STATUS") VALUES ('foo', 'ACTIVE')""")))
                .satisfies(e -> {
                    assertThat(e.getTableName()).isEqualToIgnoringCase("TEST_TABLE");
                    assertThat(e.getConstraintName()).isNotBlank();
                    assertThat(e.getSqlState()).isEqualTo("23505");
                });
    }

    @Test
    void shouldTranslateNotNullConstraintViolation() {
        assertThatExceptionOfType(NotNullConstraintViolationException.class)
                .isThrownBy(() -> jdbi.useHandle(handle -> handle.execute("""
                        INSERT INTO "TEST_TABLE" ("NAME", "STATUS") VALUES (NULL, 'ACTIVE')""")))
                .satisfies(e -> {
                    assertThat(e.getTableName()).isEqualToIgnoringCase("TEST_TABLE");
                    assertThat(e.getColumnName()).isEqualToIgnoringCase("NAME");
                    assertThat(e.getSqlState()).isEqualTo("23502");
                });
    }

    @Test
    void shouldTranslateCheckConstraintViolation() {
        assertThatExceptionOfType(CheckConstraintViolationException.class)
                .isThrownBy(() -> jdbi.useHandle(handle -> handle.execute("""
                        INSERT INTO "TEST_TABLE" ("NAME", "STATUS") VALUES ('bar', 'INVALID')""")))
                .satisfies(e -> {
                    assertThat(e.getTableName()).isEqualToIgnoringCase("TEST_TABLE");
                    assertThat(e.getConstraintName()).isNotBlank();
                    assertThat(e.getSqlState()).isEqualTo("23514");
                });
    }

}
