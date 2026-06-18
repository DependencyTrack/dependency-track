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
package org.dependencytrack.testing.database;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/// JUnit Jupiter extension that provisions the shared Dependency-Track
/// test database and truncates it *before* each test.
///
/// @since 5.1.0
public final class TestDatabaseExtension implements BeforeAllCallback, BeforeEachCallback {

    private boolean truncateBeforeEach = true;

    /// Disables the automatic truncation of all tables before each test.
    ///
    /// Use this when a test has special reset semantics (e.g. it must preserve some state across tests),
    /// and performs its own cleanup sequence.
    ///
    /// @return This extension.
    public TestDatabaseExtension withoutTruncation() {
        this.truncateBeforeEach = false;
        return this;
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        TestDatabaseManager.initialize();
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        if (truncateBeforeEach) {
            TestDatabaseManager.truncateTables();
        }
    }

    public void truncateTables() {
        TestDatabaseManager.truncateTables();
    }

    public String jdbcUrl() {
        return TestDatabaseManager.getJdbcUrl();
    }

    public @Nullable String username() {
        return TestDatabaseManager.getUsername();
    }

    public @Nullable String password() {
        return TestDatabaseManager.getPassword();
    }

}
