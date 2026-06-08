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

import org.postgresql.ds.PGSimpleDataSource;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectionsTest {

    @Test
    void shouldHardenTargetDataSourceWithKeepAliveAndLoginTimeout() {
        final GlobalOptions opts = new GlobalOptions();
        opts.targetUrl = "jdbc:postgresql://localhost:5432/dtrack";
        opts.targetUser = "u";
        opts.targetPass = "p";

        final DataSource ds = Connections.targetDataSource(opts);

        assertThat(ds).isInstanceOf(PGSimpleDataSource.class);
        final PGSimpleDataSource pg = (PGSimpleDataSource) ds;
        assertThat(pg.getTcpKeepAlive()).isTrue();
        assertThat(pg.getLoginTimeout()).isEqualTo(30);
        assertThat(pg.getSocketTimeout()).isZero();
    }

    @Test
    void shouldPropagateSocketTimeoutWhenSet() {
        final GlobalOptions opts = new GlobalOptions();
        opts.targetUrl = "jdbc:postgresql://localhost:5432/dtrack";
        opts.socketTimeoutSeconds = 120;

        final DataSource ds = Connections.targetDataSource(opts);

        assertThat(((PGSimpleDataSource) ds).getSocketTimeout()).isEqualTo(120);
    }

    @Test
    void shouldLeaveSocketTimeoutDisabledWhenZero() {
        final GlobalOptions opts = new GlobalOptions();
        opts.targetUrl = "jdbc:postgresql://localhost:5432/dtrack";
        opts.socketTimeoutSeconds = 0;

        final DataSource ds = Connections.targetDataSource(opts);

        assertThat(((PGSimpleDataSource) ds).getSocketTimeout()).isZero();
    }
}
