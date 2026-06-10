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

    /**
     * Initial-connect timeout (seconds). Bounds the auth/startup exchange that
     * {@code connectTimeout} (PG JDBC default 10s) does not cover. Without this,
     * a stalled handshake can hang indefinitely.
     */
    private static final int LOGIN_TIMEOUT_SECONDS = 30;

    private Connections() {
    }

    public static Jdbi targetJdbi(final GlobalOptions opts) {
        return Jdbi.create(buildTargetDataSource(opts));
    }

    /**
     * Single-connection DataSource for tools that need one (Flyway). PGSimpleDataSource is
     * intentionally minimal — Flyway opens its own connection on each migration step, and
     * the migrator's bootstrap is serial, so there is no need for a pool.
     */
    public static DataSource targetDataSource(final GlobalOptions opts) {
        return buildTargetDataSource(opts);
    }

    public static Connection openSource(final SourceOptions opts) throws SQLException {
        final Properties props = new Properties();
        if (opts.sourceUser != null) {
            props.setProperty("user", opts.sourceUser);
        }
        if (opts.sourcePass != null) {
            props.setProperty("password", opts.sourcePass);
        }
        // tcpKeepAlive is a PostgreSQL JDBC-specific property; MSSQL would error on
        // unknown keys, so only set it for PG sources. Other flavors get OS defaults.
        if (opts.sourceUrl != null && opts.sourceUrl.startsWith("jdbc:postgresql:")) {
            props.setProperty("tcpKeepAlive", "true");
        }
        return DriverManager.getConnection(opts.sourceUrl, props);
    }

    private static PGSimpleDataSource buildTargetDataSource(final GlobalOptions opts) {
        final PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(opts.targetUrl);
        if (opts.targetUser != null) {
            ds.setUser(opts.targetUser);
        }
        if (opts.targetPass != null) {
            ds.setPassword(opts.targetPass);
        }
        applyHardening(ds, opts);
        return ds;
    }

    /**
     * Applies network-reliability settings that PG JDBC ships with disabled or unbounded.
     * Without these, a silently broken TCP connection (k8s/NAT/LB idle drop, peer crash,
     * stateful firewall reaping the flow) leaves the driver blocked forever in a socket
     * read — see #6292, where the load phase hung for 113h on COMPONENT with no
     * observable backend session.
     */
    private static void applyHardening(final PGSimpleDataSource ds, final GlobalOptions opts) {
        // OS-level dead-peer detection. Linux probes after ~2h by default (tunable via
        // tcp_keepalive_time/_intvl/_probes); converts a dead-but-unclosed socket into a
        // SocketException -> SQLException that propagates out of inTransaction(...).
        ds.setTcpKeepAlive(true);
        ds.setLoginTimeout(LOGIN_TIMEOUT_SECONDS);
        if (opts.socketTimeoutSeconds > 0) {
            ds.setSocketTimeout(opts.socketTimeoutSeconds);
        }
    }
}
