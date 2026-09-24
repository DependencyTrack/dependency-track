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
package org.dependencytrack.dex.listener;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEvent;
import org.dependencytrack.kevdatasource.BuiltinKevDataSourcePlugin;
import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.support.net.OutboundConnectionPolicy;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.nvd.NvdVulnDataSourcePlugin;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_DATASOURCE_MIRRORING;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_SYSTEM;

class DataSourceMirroringNotificationEmitterTest extends PersistenceCapableTest {

    private PluginManager pluginManager;
    private DataSourceMirroringNotificationEmitter emitter;

    @BeforeEach
    void beforeEach() {
        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                _ -> null,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                OutboundConnectionPolicy.of(List.of("*")),
                List.of(KevDataSource.class, VulnDataSource.class));
        pluginManager.loadPlugins(List.of(new BuiltinKevDataSourcePlugin(), new NvdVulnDataSourcePlugin()));

        emitter = new DataSourceMirroringNotificationEmitter(pluginManager);
        createCatchAllNotificationRule(qm, NotificationScope.SYSTEM);
    }

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void shouldEmitInformationalNotificationForCompletedVulnDataSourceMirrorRun() {
        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of(createRunMetadata(
                "mirror-vuln-data-source", "mirror-vuln-data-source:nvd", WorkflowRunStatus.COMPLETED))));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
            assertThat(notification.getGroup()).isEqualTo(GROUP_DATASOURCE_MIRRORING);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("Data Source Mirroring");
            assertThat(notification.getContent())
                    .isEqualTo("Mirroring of vulnerability data source \"NVD\" completed successfully");
        });
    }

    @Test
    void shouldEmitErrorNotificationForFailedKevDataSourceMirrorRun() {
        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata("mirror-kev-data-source", "mirror-kev-data-source:cisa", WorkflowRunStatus.FAILED))));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
            assertThat(notification.getGroup()).isEqualTo(GROUP_DATASOURCE_MIRRORING);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_ERROR);
            assertThat(notification.getTitle()).isEqualTo("Data Source Mirroring");
            assertThat(notification.getContent())
                    .isEqualTo("Mirroring of KEV data source \"CISA KEV\" failed. Check the log for details");
        });
    }

    @Test
    void shouldFallBackToDataSourceNameWhenExtensionDoesNotExist() {
        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of(createRunMetadata(
                "mirror-vuln-data-source", "mirror-vuln-data-source:foo", WorkflowRunStatus.COMPLETED))));

        assertThat(qm.getNotificationOutbox())
                .satisfiesExactly(notification -> assertThat(notification.getContent())
                        .isEqualTo("Mirroring of vulnerability data source \"foo\" completed successfully"));
    }

    @Test
    void shouldIgnoreCancelledRuns() {
        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of(createRunMetadata(
                "mirror-vuln-data-source", "mirror-vuln-data-source:nvd", WorkflowRunStatus.CANCELLED))));

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void shouldIgnoreRunsOfOtherWorkflows() {
        emitter.onEvent(new WorkflowRunsCompletedEvent(
                List.of(createRunMetadata("vuln-analysis", null, WorkflowRunStatus.FAILED))));

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    private static WorkflowRunMetadata createRunMetadata(
            String workflowName, @Nullable String workflowInstanceId, WorkflowRunStatus status) {
        return new WorkflowRunMetadata(
                UUID.randomUUID(),
                null,
                workflowName,
                1,
                workflowInstanceId,
                "default",
                status,
                null,
                0,
                null,
                null,
                Instant.now(),
                null,
                null,
                null);
    }
}
