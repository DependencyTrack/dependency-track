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
package org.dependencytrack.pkgmetadata;

import com.github.packageurl.PackageURL;
import io.github.resilience4j.core.IntervalFunction;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageMetadataResolutionCandidatesRes;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageMetadataActivityArg;
import org.dependencytrack.secret.TestSecretManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class ResolvePackageMetadataWorkflowTest extends PersistenceCapableTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    private PluginManager pluginManager;
    private final AtomicReference<Function<PackageURL, PackageMetadata>> mockResolveFnRef =
            new AtomicReference<>(purl -> null);

    @BeforeEach
    void beforeEach() {
        final var mockPlugin = new MockPackageMetadataResolverPlugin(mockResolveFnRef);

        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                secretName -> null,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                List.of(PackageMetadataResolver.class));
        pluginManager.loadPlugins(List.of(mockPlugin));

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new ResolvePackageMetadataWorkflow(),
                voidConverter(),
                voidConverter(),
                Duration.ofSeconds(10));
        engine.registerActivity(
                new FetchPackageMetadataResolutionCandidatesActivity(pluginManager),
                voidConverter(),
                protoConverter(FetchPackageMetadataResolutionCandidatesRes.class),
                Duration.ofSeconds(5));
        engine.registerActivity(
                new ResolvePackageMetadataActivity(pluginManager, new TestSecretManager()),
                protoConverter(ResolvePackageMetadataActivityArg.class),
                voidConverter(),
                Duration.ofSeconds(10));

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "package-metadata-resolutions", 1));

        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-default", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-pkg-metadata", "package-metadata-resolutions", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();
    }

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void shouldCompleteWhenNoCandidates() {
        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final long pkgMetadataCount = withJdbiHandle(handle -> handle
                .createQuery("""
                        SELECT COUNT(*) FROM "PACKAGE_METADATA"
                        """)
                .mapTo(Long.class)
                .one());
        assertThat(pkgMetadataCount).isZero();
    }

    @Test
    void shouldResolveMetadataForComponents() {
        final Instant resolvedAt = Instant.now();

        mockResolveFnRef.set(purl -> new PackageMetadata(
                "9.9.9",
                Instant.now(),
                resolvedAt,
                new PackageArtifactMetadata(
                        resolvedAt,
                        null,
                        Map.of(
                                HashAlgorithm.MD5, "d41d8cd98f00b204e9800998ecf8427e",
                                HashAlgorithm.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                                HashAlgorithm.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                HashAlgorithm.SHA512, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"))));

        var project = new Project();
        project.setName("test-project");
        project = qm.persist(project);

        final var componentFoo = new Component();
        componentFoo.setProject(project);
        componentFoo.setGroup("org.acme");
        componentFoo.setName("foo");
        componentFoo.setVersion("1.0");
        componentFoo.setPurl("pkg:maven/org.acme/foo@1.0");
        qm.persist(componentFoo);

        final var componentBar = new Component();
        componentBar.setProject(project);
        componentBar.setGroup("org.acme");
        componentBar.setName("bar");
        componentBar.setVersion("2.0");
        componentBar.setPurl("pkg:maven/org.acme/bar@2.0");
        qm.persist(componentBar);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final List<Map<String, Object>> pkgMetadata = withJdbiHandle(handle -> handle
                .createQuery("""
                        SELECT "PURL", "LATEST_VERSION", "LATEST_VERSION_PUBLISHED_AT", "RESOLVED_BY"
                          FROM "PACKAGE_METADATA"
                         ORDER BY "PURL"
                        """)
                .mapToMap()
                .list());
        assertThat(pkgMetadata).satisfiesExactly(
                row -> {
                    assertThat(row).containsEntry("purl", "pkg:maven/org.acme/bar");
                    assertThat(row).containsEntry("latest_version", "9.9.9");
                    assertThat(row).containsKey("latest_version_published_at");
                    assertThat(row).containsEntry("resolved_by", "mock");
                },
                row -> {
                    assertThat(row).containsEntry("purl", "pkg:maven/org.acme/foo");
                    assertThat(row).containsEntry("latest_version", "9.9.9");
                    assertThat(row).containsKey("latest_version_published_at");
                    assertThat(row).containsEntry("resolved_by", "mock");
                });

        final List<Map<String, Object>> versionMetadata = withJdbiHandle(handle -> handle
                .createQuery("""
                        SELECT "PURL", "HASH_SHA256", "RESOLVED_BY"
                          FROM "PACKAGE_ARTIFACT_METADATA"
                         ORDER BY "PURL"
                        """)
                .mapToMap()
                .list());
        assertThat(versionMetadata).satisfiesExactly(
                row -> {
                    assertThat(row).containsEntry("purl", "pkg:maven/org.acme/bar@2.0");
                    assertThat(row).containsEntry("hash_sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
                    assertThat(row).containsEntry("resolved_by", "mock");
                },
                row -> {
                    assertThat(row).containsEntry("purl", "pkg:maven/org.acme/foo@1.0");
                    assertThat(row).containsEntry("hash_sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
                    assertThat(row).containsEntry("resolved_by", "mock");
                });
    }

    @Test
    void shouldPersistEmptyResultsForUnknownResolver() {
        var project = new Project();
        project.setName("test-project");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("foo");
        component.setVersion("1.0");
        component.setPurl("pkg:npm/foo@1.0");
        qm.persist(component);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final List<Map<String, Object>> pkgMetadata = withJdbiHandle(handle -> handle
                .createQuery("""
                        SELECT "PURL", "LATEST_VERSION", "LATEST_VERSION_PUBLISHED_AT"
                          FROM "PACKAGE_METADATA"
                        """)
                .mapToMap()
                .list());
        assertThat(pkgMetadata).satisfiesExactly(row -> {
            assertThat(row).containsEntry("purl", "pkg:npm/foo");
            assertThat(row).containsEntry("latest_version", null);
            assertThat(row).containsEntry("latest_version_published_at", null);
        });

        final List<Map<String, Object>> versionMetadata = withJdbiHandle(handle -> handle
                .createQuery("""
                        SELECT "PURL", "HASH_SHA256"
                          FROM "PACKAGE_ARTIFACT_METADATA"
                        """)
                .mapToMap()
                .list());
        assertThat(versionMetadata).satisfiesExactly(row -> {
            assertThat(row).containsEntry("purl", "pkg:npm/foo@1.0");
            assertThat(row).containsEntry("hash_sha256", null);
        });
    }

    @Test
    void shouldHandleResolverFailureGracefully() {
        mockResolveFnRef.set(purl -> {
            throw new RuntimeException("Simulated resolver failure");
        });

        var project = new Project();
        project.setName("test-project");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("org.acme");
        component.setName("foo");
        component.setVersion("1.0");
        component.setPurl("pkg:maven/org.acme/foo@1.0");
        qm.persist(component);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final List<Map<String, Object>> pkgMetadata = withJdbiHandle(handle -> handle
                .createQuery("""
                        SELECT "PURL", "LATEST_VERSION"
                          FROM "PACKAGE_METADATA"
                        """)
                .mapToMap()
                .list());
        assertThat(pkgMetadata).satisfiesExactly(row -> {
            assertThat(row).containsEntry("purl", "pkg:maven/org.acme/foo");
            assertThat(row).containsEntry("latest_version", null);
        });
    }

}
