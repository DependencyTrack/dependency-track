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

/// Listener for lifecycle events of the shared test database.
///
/// @since 5.1.0
public interface TestDatabaseEventListener {

    /// Invoked once per JVM, after the per-fork database has been created, with its coordinates.
    ///
    /// @param jdbcUrl  The JDBC URL of the test database.
    /// @param username The username of the test database.
    /// @param password The password of the test database.
    default void onDatabaseInitialized(
            String jdbcUrl,
            @Nullable String username,
            @Nullable String password) {
    }

    /// Invoked after the test database's tables have been truncated
    /// (i.e. before each test for consumers using [TestDatabaseExtension]).
    /// Use this to reset state that the generic truncation does not cover.
    default void onTablesTruncated() {
    }

}
