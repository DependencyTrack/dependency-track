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
package org.dependencytrack.persistence.jdbi;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.search.MeterNotFoundException;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.JdbiException;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_QUERY_NAME;

public class QueryTimingSqlLoggerTest extends PersistenceCapableTest {

    public interface TestDao {

        @SqlQuery("""
                SELECT COUNT(*) FROM "CONFIGPROPERTY"
                """)
        long getConfigPropertyCount();

    }

    private DataSource dataSource;

    @BeforeEach
    public void before() throws Exception {
        super.before();

        dataSource = DataSourceRegistry.getInstance().getDefault();
    }

    @Test
    public void shouldCaptureQueryNameForSqlObject() {
        final var meterRegistry = new SimpleMeterRegistry();

        final var jdbi = Jdbi
                .create(dataSource)
                .installPlugin(new SqlObjectPlugin())
                .setSqlLogger(new QueryTimingSqlLogger(meterRegistry));

        final long configPropertyCount = jdbi.withExtension(TestDao.class, TestDao::getConfigPropertyCount);
        assertThat(configPropertyCount).isZero();

        final Timer latencyTimer = meterRegistry.get("jdbi.query.latency").timer();
        assertThat(latencyTimer).isNotNull();

        final Meter.Id latencyTimerId = latencyTimer.getId();
        assertThat(latencyTimerId.getTag("query")).isEqualTo("TestDao#getConfigPropertyCount");
        assertThat(latencyTimerId.getTag("outcome")).isEqualTo("success");
    }

    @Test
    public void shouldCaptureExplicitQueryName() {
        final var meterRegistry = new SimpleMeterRegistry();

        final var jdbi = Jdbi
                .create(dataSource)
                .installPlugin(new SqlObjectPlugin())
                .setSqlLogger(new QueryTimingSqlLogger(meterRegistry));

        final long configPropertyCount = jdbi.withHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*) FROM "CONFIGPROPERTY"
                        """)
                .define(ATTRIBUTE_QUERY_NAME, "someQueryName")
                .mapTo(Long.class)
                .one());
        assertThat(configPropertyCount).isZero();

        final Timer latencyTimer = meterRegistry.get("jdbi.query.latency").timer();
        assertThat(latencyTimer).isNotNull();

        final Meter.Id latencyTimerId = latencyTimer.getId();
        assertThat(latencyTimerId.getTag("query")).isEqualTo("someQueryName");
        assertThat(latencyTimerId.getTag("outcome")).isEqualTo("success");
    }

    @Test
    public void shouldNotCaptureUnnamedQueries() {
        final var meterRegistry = new SimpleMeterRegistry();

        final var jdbi = Jdbi
                .create(dataSource)
                .installPlugin(new SqlObjectPlugin())
                .setSqlLogger(new QueryTimingSqlLogger(meterRegistry));

        final long configPropertyCount = jdbi.withHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*) FROM "CONFIGPROPERTY"
                        """)
                .mapTo(Long.class)
                .one());
        assertThat(configPropertyCount).isZero();

        assertThatExceptionOfType(MeterNotFoundException.class)
                .isThrownBy(() -> meterRegistry.get("jdbi.query.latency").timer());
    }

    @Test
    public void shouldCaptureQueryNameForFailure() {
        final var meterRegistry = new SimpleMeterRegistry();

        final var jdbi = Jdbi
                .create(dataSource)
                .installPlugin(new SqlObjectPlugin())
                .setSqlLogger(new QueryTimingSqlLogger(meterRegistry));

        assertThatExceptionOfType(JdbiException.class)
                .isThrownBy(() -> jdbi.withHandle(handle -> handle.createQuery("""
                                SELECT COUNT(*) FROM does_not_exist
                                """)
                        .define(ATTRIBUTE_QUERY_NAME, "someQueryName")
                        .mapTo(Long.class)
                        .one()));

        final Timer latencyTimer = meterRegistry.get("jdbi.query.latency").timer();
        assertThat(latencyTimer).isNotNull();

        final Meter.Id latencyTimerId = latencyTimer.getId();
        assertThat(latencyTimerId.getTag("query")).isEqualTo("someQueryName");
        assertThat(latencyTimerId.getTag("outcome")).isEqualTo("failure");
    }

}