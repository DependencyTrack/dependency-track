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
package org.dependencytrack.v4migrator.transform;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SqlStatementSplitterTest {

    @Test
    void splitsTopLevelSemicolons() {
        final List<String> stmts = SqlStatementSplitter.split("CREATE TABLE t (id int); INSERT INTO t VALUES (1);");
        assertThat(stmts).containsExactly(
            "CREATE TABLE t (id int)",
            "INSERT INTO t VALUES (1)"
        );
    }

    @Test
    void ignoresSemicolonInsideLineComment() {
        final List<String> stmts = SqlStatementSplitter.split("""
            -- a comment with ; inside
            SELECT 1;
            -- another ; comment
            SELECT 2
            """);
        assertThat(stmts).hasSize(2);
        assertThat(stmts.get(0)).contains("SELECT 1").contains("a comment");
        assertThat(stmts.get(1)).contains("SELECT 2");
    }

    @Test
    void ignoresSemicolonInsideBlockComment() {
        final List<String> stmts = SqlStatementSplitter.split("/* outer ; /* nested ; */ ; */ SELECT 1; SELECT 2;");
        assertThat(stmts).hasSize(2);
    }

    @Test
    void ignoresSemicolonInsideSingleQuoteString() {
        final List<String> stmts = SqlStatementSplitter.split("INSERT INTO t VALUES ('a;b'); SELECT 1;");
        assertThat(stmts).hasSize(2);
        assertThat(stmts.get(0)).isEqualTo("INSERT INTO t VALUES ('a;b')");
    }

    @Test
    void handlesEscapedSingleQuote() {
        final List<String> stmts = SqlStatementSplitter.split("SELECT 'a''b;c'; SELECT 2;");
        assertThat(stmts).hasSize(2);
        assertThat(stmts.get(0)).isEqualTo("SELECT 'a''b;c'");
    }

    @Test
    void ignoresSemicolonInsideDollarQuotedBlock() {
        final List<String> stmts = SqlStatementSplitter.split("""
            DO $$
            BEGIN
                PERFORM 1;
                PERFORM 2;
            END $$;
            SELECT 1;
            """);
        assertThat(stmts).hasSize(2);
        assertThat(stmts.get(0)).startsWith("DO $$").endsWith("$$");
        assertThat(stmts.get(1)).isEqualTo("SELECT 1");
    }

    @Test
    void ignoresSemicolonInsideTaggedDollarQuote() {
        final List<String> stmts = SqlStatementSplitter.split("DO $body$ BEGIN PERFORM 1; END $body$; SELECT 2;");
        assertThat(stmts).hasSize(2);
    }

    @Test
    void ignoresSemicolonInsideDoubleQuotedIdentifier() {
        final List<String> stmts = SqlStatementSplitter.split("SELECT \"weird;column\" FROM t; SELECT 2;");
        assertThat(stmts).hasSize(2);
    }
}
