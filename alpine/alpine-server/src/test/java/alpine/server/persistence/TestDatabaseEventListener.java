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
package alpine.server.persistence;

import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.jspecify.annotations.NullMarked;

@NullMarked
public final class TestDatabaseEventListener implements org.dependencytrack.testing.database.TestDatabaseEventListener {

    @Override
    public void onDatabaseInitialized(String jdbcUrl, String username, String password) {
        MemoryConfigSource.setProperty("dt.datasource.url", jdbcUrl);
        MemoryConfigSource.setProperty("dt.datasource.username", username);
        MemoryConfigSource.setProperty("dt.datasource.password", password);

        new PersistenceManagerFactory().contextInitialized(null);
    }

    @Override
    public void onTablesTruncated() {
        // Nothing to do.
    }
}
