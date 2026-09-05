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
package org.dependencytrack.resources.v2;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRun;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.proto.failure.v1.ActivityFailureDetails;
import org.dependencytrack.dex.proto.failure.v1.Failure;
import org.dependencytrack.kevdatasource.KevDataSourceMirrorService;
import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.kevdatasource.api.KevDataSourceFactory;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.secret.TestSecretManager;
import org.dependencytrack.secret.management.SecretManager;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentMatchers;

import jakarta.ws.rs.core.Response;

import java.net.http.HttpClient;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

class KevDataSourcesResourceTest extends ResourceTest {

    private static final DexEngine DEX_ENGINE_MOCK = mock(DexEngine.class);
    private static SecretManager secretManager;
    private static PluginManager pluginManager;
    private static KevDataSourceMirrorService mirrorService;

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig().register(new AbstractBinder() {
        @Override
        protected void configure() {
            bindFactory(() -> mirrorService).to(KevDataSourceMirrorService.class);
        }
    }));

    @BeforeAll
    static void beforeAll() {
        secretManager = new TestSecretManager();
    }

    @BeforeEach
    void beforeEach() {
        reset(DEX_ENGINE_MOCK);
        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                secretManager::getSecretValue,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                List.of(KevDataSource.class));
        mirrorService = new KevDataSourceMirrorService(pluginManager, DEX_ENGINE_MOCK);
    }

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void shouldTriggerMirror() {
        loadFactory(new DummyKevDataSourceFactory("cisa", true));
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        when(DEX_ENGINE_MOCK.createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any()))
                .thenReturn(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        final Response response = jersey.target("/kev-data-sources/cisa/mirror-runs")
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

        assertThat(response.getStatus()).isEqualTo(202);
        assertThat(response.getHeaderString("Location")).endsWith("/kev-data-sources/cisa/mirror-runs/latest");
        assertThat(getPlainTextBody(response)).isEmpty();
    }

    @Test
    void shouldReturnConflictWhenMirrorAlreadyInProgress() {
        loadFactory(new DummyKevDataSourceFactory("cisa", true));
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        when(DEX_ENGINE_MOCK.createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any()))
                .thenReturn(null);

        final Response response = jersey.target("/kev-data-sources/cisa/mirror-runs")
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

        assertThat(response.getStatus()).isEqualTo(409);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "/problems/kev-data-source-mirror-already-running",
                  "status": 409,
                  "title": "Conflict",
                  "detail": "A mirror run for this data source is already in progress"
                }
                """);
    }

    @Test
    void shouldReturnBadRequestWhenDataSourceNotEnabled() {
        loadFactory(new DummyKevDataSourceFactory("cisa", false));
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey.target("/kev-data-sources/cisa/mirror-runs")
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "/problems/kev-data-source-not-enabled",
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "The KEV data source is not enabled"
                }
                """);
    }

    @Test
    void shouldReturnNotFoundWhenTriggeringUnknownDataSource() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey.target("/kev-data-sources/does-not-exist/mirror-runs")
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldReturnForbiddenWhenTriggeringWithoutPermission() {
        loadFactory(new DummyKevDataSourceFactory("cisa", true));
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey.target("/kev-data-sources/cisa/mirror-runs")
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldReturnNotFoundWhenNoRunExists() {
        loadFactory(new DummyKevDataSourceFactory("cisa", true));
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        when(DEX_ENGINE_MOCK.listRuns(any(ListWorkflowRunsRequest.class)))
                .thenReturn(new Page<>(List.of(), null, null));

        final Response response = jersey.target("/kev-data-sources/cisa/mirror-runs/latest")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldReturnNotFoundWhenGettingStatusOfUnknownDataSource() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey.target("/kev-data-sources/does-not-exist/mirror-runs/latest")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldReturnRunningStatus() {
        loadFactory(new DummyKevDataSourceFactory("cisa", true));
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var runId = UUID.fromString("00000000-0000-0000-0000-000000000002");
        final var startedAt = Instant.parse("2026-04-15T10:00:00Z");

        when(DEX_ENGINE_MOCK.listRuns(any(ListWorkflowRunsRequest.class)))
                .thenReturn(new Page<>(
                        List.of(new WorkflowRunMetadata(
                                runId,
                                null,
                                "MirrorKevDataSourceWorkflow",
                                1,
                                "mirror-kev-data-source:cisa",
                                "default",
                                WorkflowRunStatus.RUNNING,
                                null,
                                0,
                                null,
                                null,
                                startedAt,
                                startedAt,
                                startedAt,
                                null)),
                        null,
                        null));

        final Response response = jersey.target("/kev-data-sources/cisa/mirror-runs/latest")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                {
                  "status": "RUNNING",
                  "started_at": %d
                }
                """.formatted(startedAt.toEpochMilli()));
    }

    @Test
    void shouldReturnStatusWithFailureReasonWhenRunFailed() {
        loadFactory(new DummyKevDataSourceFactory("cisa", true));
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var runId = UUID.fromString("00000000-0000-0000-0000-000000000003");
        final var startedAt = Instant.parse("2026-04-15T10:00:00Z");
        final var completedAt = Instant.parse("2026-04-15T10:01:00Z");

        final var runMetadata = new WorkflowRunMetadata(
                runId,
                null,
                "MirrorKevDataSourceWorkflow",
                1,
                "mirror-kev-data-source:cisa",
                "default",
                WorkflowRunStatus.FAILED,
                null,
                0,
                null,
                null,
                startedAt,
                completedAt,
                startedAt,
                completedAt);

        final var failure = Failure.newBuilder()
                .setMessage("activity failed")
                .setActivityFailureDetails(ActivityFailureDetails.newBuilder()
                        .setActivityName("MirrorKevDataSourceActivity")
                        .build())
                .setCause(Failure.newBuilder().setMessage("connection refused").build())
                .build();

        final var run = new WorkflowRun(
                runId,
                null,
                "MirrorKevDataSourceWorkflow",
                1,
                "mirror-kev-data-source:cisa",
                WorkflowRunStatus.FAILED,
                null,
                0,
                null,
                null,
                startedAt,
                completedAt,
                startedAt,
                completedAt,
                null,
                null,
                failure,
                List.of());

        when(DEX_ENGINE_MOCK.listRuns(any(ListWorkflowRunsRequest.class)))
                .thenReturn(new Page<>(List.of(runMetadata), null, null));
        when(DEX_ENGINE_MOCK.getRunById(runId)).thenReturn(run);

        final Response response = jersey.target("/kev-data-sources/cisa/mirror-runs/latest")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                {
                  "status": "FAILED",
                  "started_at": %d,
                  "completed_at": %d,
                  "failure_reason": "connection refused"
                }
                """.formatted(startedAt.toEpochMilli(), completedAt.toEpochMilli()));
    }

    @Test
    void shouldReturnGenericFailureReasonWhenCauseAbsent() {
        loadFactory(new DummyKevDataSourceFactory("cisa", true));
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var runId = UUID.fromString("00000000-0000-0000-0000-000000000004");
        final var startedAt = Instant.parse("2026-04-15T10:00:00Z");
        final var completedAt = Instant.parse("2026-04-15T10:01:00Z");

        final var runMetadata = new WorkflowRunMetadata(
                runId,
                null,
                "MirrorKevDataSourceWorkflow",
                1,
                "mirror-kev-data-source:cisa",
                "default",
                WorkflowRunStatus.FAILED,
                null,
                0,
                null,
                null,
                startedAt,
                completedAt,
                startedAt,
                completedAt);

        final var failure = Failure.newBuilder()
                .setMessage("activity failed")
                .setActivityFailureDetails(ActivityFailureDetails.newBuilder()
                        .setActivityName("MirrorKevDataSourceActivity")
                        .build())
                .build();

        final var run = new WorkflowRun(
                runId,
                null,
                "MirrorKevDataSourceWorkflow",
                1,
                "mirror-kev-data-source:cisa",
                WorkflowRunStatus.FAILED,
                null,
                0,
                null,
                null,
                startedAt,
                completedAt,
                startedAt,
                completedAt,
                null,
                null,
                failure,
                List.of());

        when(DEX_ENGINE_MOCK.listRuns(any(ListWorkflowRunsRequest.class)))
                .thenReturn(new Page<>(List.of(runMetadata), null, null));
        when(DEX_ENGINE_MOCK.getRunById(runId)).thenReturn(run);

        final Response response = jersey.target("/kev-data-sources/cisa/mirror-runs/latest")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                {
                  "status": "FAILED",
                  "started_at": %d,
                  "completed_at": %d,
                  "failure_reason": "Unknown failure"
                }
                """.formatted(startedAt.toEpochMilli(), completedAt.toEpochMilli()));
    }

    private static void loadFactory(KevDataSourceFactory factory) {
        pluginManager.loadPlugins(List.of(() -> List.of(factory)));
    }

    private static final class DummyKevDataSource implements KevDataSource {
        @Override
        public boolean hasNext() {
            return false;
        }

        @Override
        public KevAssertion next() {
            throw new NoSuchElementException();
        }
    }

    private static final class DummyKevDataSourceFactory implements KevDataSourceFactory {

        private final String name;
        private final boolean enabled;

        DummyKevDataSourceFactory(String name, boolean enabled) {
            this.name = name;
            this.enabled = enabled;
        }

        @Override
        public @NonNull String extensionName() {
            return name;
        }

        @Override
        public @NonNull String displayName() {
            return name;
        }

        @Override
        public @NonNull Class<? extends KevDataSource> extensionClass() {
            return DummyKevDataSource.class;
        }

        @Override
        public int priority() {
            return PRIORITY_HIGHEST;
        }

        @Override
        public void init(@NonNull ServiceRegistry serviceRegistry) {}

        @Override
        public boolean isEnabled() {
            return enabled;
        }

        @Override
        public @NonNull KevDataSource create() {
            throw new UnsupportedOperationException();
        }
    }
}
