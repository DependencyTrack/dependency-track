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
package org.dependencytrack.v4migrator.config;

import org.jdbi.v3.core.Jdbi;
import org.postgresql.ds.PGSimpleDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

public final class Connections {

    private Connections() {
    }

    public static Jdbi targetJdbi(final GlobalOptions opts) {
        return Jdbi.create(opts.targetUrl, opts.targetUser, opts.targetPass);
    }

    /**
     * Single-connection DataSource for tools that need one (Flyway). PGSimpleDataSource is
     * intentionally minimal — Flyway opens its own connection on each migration step, and
     * the migrator's bootstrap is serial, so there is no need for a pool.
     */
    public static DataSource targetDataSource(final GlobalOptions opts) {
        final PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(opts.targetUrl);
        if (opts.targetUser != null) {
            ds.setUser(opts.targetUser);
        }
        if (opts.targetPass != null) {
            ds.setPassword(opts.targetPass);
        }
        return ds;
    }

    public static Connection openSource(final SourceOptions opts) throws SQLException {
        final Properties props = new Properties();
        if (opts.sourceUser != null) {
            props.setProperty("user", opts.sourceUser);
        }
        if (opts.sourcePass != null) {
            props.setProperty("password", opts.sourcePass);
        }
        return DriverManager.getConnection(opts.sourceUrl, props);
    }
}
