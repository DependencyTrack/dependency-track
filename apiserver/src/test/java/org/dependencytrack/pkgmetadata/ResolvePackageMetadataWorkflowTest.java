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
import org.dependencytrack.model.PackageMetadataResolutionStatus;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.persistence.jdbi.PackageArtifactMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataResolutionDao;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageMetadataResolutionCandidatesArg;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageMetadataResolutionCandidatesRes;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageMetadataActivityArg;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageMetadataWorkflowArg;
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
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class ResolvePackageMetadataWorkflowTest extends PersistenceCapableTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    private PluginManager pluginManager;
    private final AtomicReference<Function<PackageURL, PackageMetadata>> mockResolveFnRef =
            new AtomicReference<>(_ -> null);
    private final AtomicReference<PackageArtifactMetadata> mockLastSeenPriorRef =
            new AtomicReference<>(null);

    @BeforeEach
    void beforeEach() {
        final var mockPlugin = new MockPackageMetadataResolverPlugin(mockResolveFnRef, mockLastSeenPriorRef);

        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                _ -> null,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                List.of(PackageMetadataResolver.class));
        pluginManager.loadPlugins(List.of(mockPlugin));

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new ResolvePackageMetadataWorkflow(),
                protoConverter(ResolvePackageMetadataWorkflowArg.class),
                voidConverter(),
                Duration.ofSeconds(10));
        engine.registerActivity(
                new FetchPackageMetadataResolutionCandidatesActivity(
                        pluginManager,
                        /* resolveBatchSize */ 2),
                protoConverter(FetchPackageMetadataResolutionCandidatesArg.class),
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

        mockResolveFnRef.set(_ -> new PackageMetadata(
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
        qm.createComponent(componentFoo, false);

        final var componentBar = new Component();
        componentBar.setProject(project);
        componentBar.setGroup("org.acme");
        componentBar.setName("bar");
        componentBar.setVersion("2.0");
        componentBar.setPurl("pkg:maven/org.acme/bar@2.0");
        qm.createComponent(componentBar, false);

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
    void shouldRecordNotFoundResolutionForUnknownResolver() {
        var project = new Project();
        project.setName("test-project");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("foo");
        component.setVersion("1.0");
        component.setPurl("pkg:npm/foo@1.0");
        qm.createComponent(component, false);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(resolutionRows()).satisfiesExactly(row -> {
            assertThat(row).containsEntry("purl", "pkg:npm/foo@1.0");
            assertThat(row).containsEntry("status", "NOT_FOUND");
        });
        assertThat(rowCountOfTable("PACKAGE_METADATA")).isZero();
        assertThat(rowCountOfTable("PACKAGE_ARTIFACT_METADATA")).isZero();
    }

    @Test
    void shouldRecordUnresolvableResolutionForMalformedPurl() {
        var project = new Project();
        project.setName("test-project");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("foo");
        component.setVersion("1.0");
        component.setPurl("pkg:npm/foo%ZZ@1.0");
        qm.createComponent(component, false);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(resolutionRows()).satisfiesExactly(row -> {
            assertThat(row).containsEntry("purl", "pkg:npm/foo%ZZ@1.0");
            assertThat(row).containsEntry("status", "UNRESOLVABLE");
        });
    }

    @Test
    void shouldPageThroughCandidatesAcrossMultipleBatches() {
        final Instant resolvedAt = Instant.now();
        mockResolveFnRef.set(_ -> new PackageMetadata("9.9.9", Instant.now(), resolvedAt, null));

        var project = new Project();
        project.setName("test-project");
        project = qm.persist(project);

        for (final String name : List.of("a", "b", "c", "d", "e")) {
            final var component = new Component();
            component.setProject(project);
            component.setGroup("org.acme");
            component.setName(name);
            component.setVersion("1.0");
            component.setPurl("pkg:maven/org.acme/" + name + "@1.0");
            qm.createComponent(component, false);
        }

        // Pre-suppress "c" with a fresh EMPTY record. It must be skipped as a non-candidate
        // while the cursor still advances past it to reach "d" and "e" in later batches.
        useJdbiTransaction(handle -> new PackageMetadataResolutionDao(handle)
                .upsertAll(Map.of("pkg:maven/org.acme/c@1.0", PackageMetadataResolutionStatus.NOT_FOUND)));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(resolutionRows()).satisfiesExactly(
                row -> {
                    assertThat(row).containsEntry("purl", "pkg:maven/org.acme/a@1.0");
                    assertThat(row).containsEntry("status", "RESOLVED");
                },
                row -> {
                    assertThat(row).containsEntry("purl", "pkg:maven/org.acme/b@1.0");
                    assertThat(row).containsEntry("status", "RESOLVED");
                },
                row -> {
                    assertThat(row).containsEntry("purl", "pkg:maven/org.acme/c@1.0");
                    assertThat(row).containsEntry("status", "NOT_FOUND");
                },
                row -> {
                    assertThat(row).containsEntry("purl", "pkg:maven/org.acme/d@1.0");
                    assertThat(row).containsEntry("status", "RESOLVED");
                },
                row -> {
                    assertThat(row).containsEntry("purl", "pkg:maven/org.acme/e@1.0");
                    assertThat(row).containsEntry("status", "RESOLVED");
                });
    }

    @Test
    void shouldReResolveStalePurlButSkipFreshOne() {
        final Instant resolvedAt = Instant.now();
        mockResolveFnRef.set(_ -> new PackageMetadata("9.9.9", Instant.now(), resolvedAt, null));

        var project = new Project();
        project.setName("test-project");
        project = qm.persist(project);

        for (final String name : List.of("stale", "fresh")) {
            final var component = new Component();
            component.setProject(project);
            component.setGroup("org.acme");
            component.setName(name);
            component.setVersion("1.0");
            component.setPurl("pkg:maven/org.acme/" + name + "@1.0");
            qm.createComponent(component, false);
        }

        final Instant now = Instant.now();
        useJdbiTransaction(handle -> handle
                .createUpdate("""
                        UPDATE "PACKAGE_METADATA_RESOLUTION"
                           SET "STATUS" = v.status
                             , "LAST_ATTEMPTED_AT" = v.last_attempted_at
                          FROM (
                            VALUES ('pkg:maven/org.acme/stale@1.0', 'RESOLVED', CAST(:now AS TIMESTAMPTZ) - INTERVAL '25 hours')
                                 , ('pkg:maven/org.acme/fresh@1.0', 'RESOLVED', CAST(:now AS TIMESTAMPTZ) - INTERVAL '23 hours')
                          ) AS v(purl, status, last_attempted_at)
                         WHERE "PURL" = v.purl
                        """)
                .bind("now", now)
                .execute());

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final Instant threshold = now.minus(Duration.ofHours(1));
        assertThat(lastAttemptedAt("pkg:maven/org.acme/stale@1.0")).isAfter(threshold);
        assertThat(lastAttemptedAt("pkg:maven/org.acme/fresh@1.0")).isBefore(threshold);
    }

    @Test
    void shouldResolveDuePurlEvenWithoutComponent() {
        // NB: Orphan rows are deliberately swept until the maintenance task removes them,
        // keeping the candidate query's cost bounded by the batch size alone.
        useJdbiTransaction(handle -> handle
                .createUpdate("""
                        INSERT INTO "PACKAGE_METADATA_RESOLUTION" ("PURL", "STATUS")
                        VALUES (:purl, 'PENDING')
                        """)
                .bind("purl", "pkg:maven/org.acme/orphan@1.0")
                .execute());

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(resolutionRows()).satisfiesExactly(row -> {
            assertThat(row).containsEntry("purl", "pkg:maven/org.acme/orphan@1.0");
            assertThat(row).containsEntry("status", "NOT_FOUND");
        });
        assertThat(rowCountOfTable("PACKAGE_METADATA")).isZero();
    }

    @Test
    void shouldPassPriorArtifactMetadataToResolverWhenAvailable() {
        useJdbiTransaction(handle -> {
            new PackageMetadataDao(handle).upsertAll(List.of(
                    new org.dependencytrack.model.PackageMetadata(
                            parsePurl("pkg:maven/org.acme/foo"),
                            "1.0",
                            Instant.parse("2024-06-15T12:00:00Z"),
                            Instant.parse("2024-06-15T12:00:00Z"),
                            null,
                            "mock")));
            new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                    new org.dependencytrack.model.PackageArtifactMetadata(
                            parsePurl("pkg:maven/org.acme/foo@1.0"),
                            parsePurl("pkg:maven/org.acme/foo"),
                            null,
                            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            null,
                            null,
                            Instant.parse("2024-06-15T12:00:00Z"),
                            "mock",
                            null,
                            Instant.parse("2024-06-15T12:00:00Z"))));
        });

        final Instant resolvedAt = Instant.now();
        mockResolveFnRef.set(_ -> new PackageMetadata("9.9.9", Instant.now(), resolvedAt, null));

        var project = new Project();
        project.setName("test-project");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("org.acme");
        component.setName("foo");
        component.setVersion("1.0");
        component.setPurl("pkg:maven/org.acme/foo@1.0");
        qm.createComponent(component, false);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final PackageArtifactMetadata seenPrior = mockLastSeenPriorRef.get();
        assertThat(seenPrior).isNotNull();
        assertThat(seenPrior.publishedAt()).isEqualTo(Instant.parse("2024-06-15T12:00:00Z"));
        assertThat(seenPrior.hashes()).containsEntry(HashAlgorithm.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    @Test
    void shouldHandleResolverFailureGracefully() {
        mockResolveFnRef.set(_ -> {
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
        qm.createComponent(component, false);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(resolutionRows()).satisfiesExactly(row -> {
            assertThat(row).containsEntry("purl", "pkg:maven/org.acme/foo@1.0");
            assertThat(row).containsEntry("status", "NOT_FOUND");
        });
        assertThat(rowCountOfTable("PACKAGE_METADATA")).isZero();
    }

    @Test
    void shouldFailTerminallyOnMalformedCursor() {
        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class)
                        .withArgument(ResolvePackageMetadataWorkflowArg.newBuilder()
                                .setCursor("cursor-without-delimiter")
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);
    }

    private static PackageURL parsePurl(String purl) {
        try {
            return new PackageURL(purl);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static List<Map<String, Object>> resolutionRows() {
        return withJdbiHandle(handle -> handle
                .createQuery("""
                        SELECT "PURL"
                             , "STATUS"
                          FROM "PACKAGE_METADATA_RESOLUTION"
                         ORDER BY "PURL"
                        """)
                .mapToMap()
                .list());
    }

    private static long rowCountOfTable(String table) {
        return withJdbiHandle(handle -> handle
                .createQuery("SELECT COUNT(*) FROM \"" + table + "\"")
                .mapTo(Long.class)
                .one());
    }

    private static Instant lastAttemptedAt(String purl) {
        return withJdbiHandle(handle -> handle
                .createQuery("""
                        SELECT "LAST_ATTEMPTED_AT"
                          FROM "PACKAGE_METADATA_RESOLUTION"
                         WHERE "PURL" = :purl
                        """)
                .bind("purl", purl)
                .mapTo(Instant.class)
                .one());
    }

}
