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
package org.dependencytrack.kevdatasource;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.kevdatasource.api.KevDataSourceFactory;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.MirrorKevDataSourceArg;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.util.Iterator;
import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.Mockito.mock;

class MirrorKevDataSourceActivityTest extends PersistenceCapableTest {

    private final ActivityContext ctx = mock(ActivityContext.class);

    private PluginManager pluginManager;

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void shouldMirrorEnabledSource() throws Exception {
        final var activity = new MirrorKevDataSourceActivity(
                createPluginManager(
                        "cisa", () -> kevDataSourceOf(
                                new KevAssertion(
                                        "NVD",
                                        "CVE-1",
                                        null,
                                        null,
                                        null,
                                        null,
                                        JsonNodeFactory.instance.objectNode()),
                                new KevAssertion(
                                        "NVD",
                                        "CVE-2",
                                        null,
                                        null,
                                        null,
                                        null,
                                        JsonNodeFactory.instance.objectNode()))));

        activity.execute(ctx, activityArgForKevDataSource("cisa"));

        assertThat(countKevAssertions("cisa")).isEqualTo(2);
    }

    @Test
    void shouldMirrorAcrossMultipleBatchesAndReconcile() throws Exception {
        final var activity = new MirrorKevDataSourceActivity(
                createPluginManager("cisa", providingKevDataSources(
                        kevDataSourceOf(createKevAssertions(2500)),
                        kevDataSourceOf(createKevAssertions(1500)))));

        activity.execute(ctx, activityArgForKevDataSource("cisa"));
        assertThat(countKevAssertions("cisa")).isEqualTo(2500);

        activity.execute(ctx, activityArgForKevDataSource("cisa"));
        assertThat(countKevAssertions("cisa")).isEqualTo(1500);
    }

    @Test
    void shouldNotPurgeExistingAssertionsWhenSourceReportsZero() throws Exception {
        final var activity = new MirrorKevDataSourceActivity(
                createPluginManager("cisa", providingKevDataSources(
                        kevDataSourceOf(createKevAssertions(2)),
                        kevDataSourceOf())));

        activity.execute(ctx, activityArgForKevDataSource("cisa"));
        assertThat(countKevAssertions("cisa")).isEqualTo(2);

        activity.execute(ctx, activityArgForKevDataSource("cisa"));
        assertThat(countKevAssertions("cisa")).isEqualTo(2);
    }

    @Test
    void shouldFailTerminallyWhenSourceDisabled() {
        final var activity = new MirrorKevDataSourceActivity(
                createPluginManager(List.of(
                        new DisabledKevDataSourceFactory("cisa"))));

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> activity.execute(ctx, activityArgForKevDataSource("cisa")));
    }

    @Test
    void shouldFailTerminallyWhenSourceNotFound() {
        final var activity = new MirrorKevDataSourceActivity(
                createPluginManager(List.of()));

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> activity.execute(ctx, activityArgForKevDataSource("nonexistent")));
    }

    private PluginManager createPluginManager(String name, Supplier<KevDataSource> dataSourceSupplier) {
        return createPluginManager(List.of(new TestKevDataSourceFactory(name, dataSourceSupplier)));
    }

    private PluginManager createPluginManager(List<KevDataSourceFactory> factories) {
        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                _ -> null,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                List.of(KevDataSource.class));
        pluginManager.loadPlugins(List.of(() -> List.copyOf(factories)));
        return pluginManager;
    }

    private static MirrorKevDataSourceArg activityArgForKevDataSource(String name) {
        return MirrorKevDataSourceArg.newBuilder().setDataSourceName(name).build();
    }

    private static KevAssertion[] createKevAssertions(int count) {
        final var assertions = new KevAssertion[count];
        for (int i = 0; i < count; i++) {
            assertions[i] = new KevAssertion(
                    "NVD",
                    "CVE-" + i,
                    null,
                    null,
                    null,
                    null,
                    JsonNodeFactory.instance.objectNode());
        }

        return assertions;
    }

    private static Supplier<KevDataSource> providingKevDataSources(KevDataSource... dataSources) {
        final Iterator<KevDataSource> iterator = List.of(dataSources).iterator();
        return iterator::next;
    }

    private static KevDataSource kevDataSourceOf(KevAssertion... assertions) {
        final Iterator<KevAssertion> iterator = List.of(assertions).iterator();

        return new KevDataSource() {
            @Override
            public boolean hasNext() {
                return iterator.hasNext();
            }

            @Override
            public KevAssertion next() {
                return iterator.next();
            }
        };
    }

    private static int countKevAssertions(String asserter) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*)
                          FROM "KEV_ASSERTION"
                         WHERE "ASSERTER" = :asserter
                        """)
                .bind("asserter", asserter)
                .mapTo(Integer.class)
                .one());
    }

    private static class TestKevDataSourceFactory implements KevDataSourceFactory {

        private final String name;
        private final Supplier<KevDataSource> dataSourceSupplier;

        private TestKevDataSourceFactory(String name, Supplier<KevDataSource> dataSourceSupplier) {
            this.name = name;
            this.dataSourceSupplier = dataSourceSupplier;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public String extensionName() {
            return name;
        }

        @Override
        public Class<? extends KevDataSource> extensionClass() {
            return TestKevDataSource.class;
        }

        @Override
        public int priority() {
            return 0;
        }

        @Override
        public void init(ServiceRegistry serviceRegistry) {
        }

        @Override
        public KevDataSource create() {
            return dataSourceSupplier.get();
        }

    }

    private static class DisabledKevDataSourceFactory implements KevDataSourceFactory {

        private final String name;

        private DisabledKevDataSourceFactory(final String name) {
            this.name = name;
        }

        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public String extensionName() {
            return name;
        }

        @Override
        public Class<? extends KevDataSource> extensionClass() {
            return TestKevDataSource.class;
        }

        @Override
        public int priority() {
            return 0;
        }

        @Override
        public void init(ServiceRegistry serviceRegistry) {
        }

        @Override
        public KevDataSource create() {
            throw new UnsupportedOperationException();
        }

    }

    private static class TestKevDataSource implements KevDataSource {

        @Override
        public boolean hasNext() {
            throw new UnsupportedOperationException();
        }

        @Override
        public KevAssertion next() {
            throw new UnsupportedOperationException();
        }

    }

}
