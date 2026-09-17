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
package alpine.persistence;

import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.dependencytrack.testing.database.TestDatabaseExtension;

import javax.jdo.JDOHelper;
import java.util.Properties;

import static java.util.Objects.requireNonNull;

final class TestPersistenceManagerFactory {

    private TestPersistenceManagerFactory() {}

    static JDOPersistenceManagerFactory create(TestDatabaseExtension database) {
        final Properties properties = JdoProperties.required();
        properties.put("javax.jdo.option.ConnectionURL", database.jdbcUrl());
        properties.put("javax.jdo.option.ConnectionDriverName", "org.postgresql.Driver");
        properties.put("javax.jdo.option.ConnectionUserName", requireNonNull(database.username()));
        properties.put("javax.jdo.option.ConnectionPassword", requireNonNull(database.password()));
        return (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(properties, "Alpine");
    }
}
