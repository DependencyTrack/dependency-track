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
package org.dependencytrack.pkghealth;

import alpine.model.IConfigProperty.PropertyType;
import com.github.packageurl.PackageURL;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.model.PackageHealthScorecardCheck;
import org.dependencytrack.persistence.jdbi.PackageHealthMetadataDao;
import org.dependencytrack.pkghealth.analyzer.PackageHealthAnalyzer;
import org.dependencytrack.pkghealth.client.ApiRateLimitException;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.dependencytrack.pkgmetadata.PackageMetadata;
import org.dependencytrack.pkgmetadata.PackageMetadataDao;
import org.dependencytrack.proto.internal.workflow.v1.PackageHealthGitHubFetch;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_GROUPS_REGEX;
import static org.dependencytrack.model.ConfigPropertyConstants.PACKAGE_HEALTH_RESOLUTION_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ResolvePackageHealthMetadataActivityTest extends PersistenceCapableTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    private PackageHealthAnalyzer analyzer;
    private ResolvePackageHealthMetadataActivity activity;

    @BeforeEach
    void beforeEach() {
        analyzer = mock(PackageHealthAnalyzer.class);

        activity = new ResolvePackageHealthMetadataActivity(analyzer, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void shouldNotSendInternalPackagesToExternalApis() throws Exception {
        qm.createConfigProperty(
                INTERNAL_COMPONENTS_GROUPS_REGEX.getGroupName(),
                INTERNAL_COMPONENTS_GROUPS_REGEX.getPropertyName(),
                "^org\\.acme$",
                PropertyType.STRING,
                null);

        final var internalPurl = new PackageURL("pkg:maven/org.acme/secret-lib");
        final var publicPurl = new PackageURL("pkg:maven/org.example/public-lib");
        createPackageMetadata(internalPurl);
        createPackageMetadata(publicPurl);

        final var model = new AnalyzedPackageHealth(publicPurl);
        model.setStars(10L);
        when(analyzer.analyze(publicPurl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(model));

        activity.execute(
                mock(ActivityContext.class),
                ResolvePackageHealthMetadataActivityArg.newBuilder()
                        .addPurls(internalPurl.toString())
                        .addPurls(publicPurl.toString())
                        .build());

        verify(analyzer).analyze(publicPurl);
        verify(analyzer, never()).analyze(internalPurl);

        final var internalMetadata = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(internalPurl));
        assertThat(internalMetadata).isNotNull();
        assertThat(internalMetadata.status()).isEqualTo(PackageHealthMetadataStatus.NOT_AVAILABLE);
        assertThat(internalMetadata.lastFetch()).isEqualTo(NOW);
    }

    @Test
    void shouldFetchAndPersistAvailableMetadata() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var packagePurl = new PackageURL("pkg:npm/example");

        createPackageMetadata(packagePurl);

        final var model = new AnalyzedPackageHealth(packagePurl);
        model.setStars(100L);
        model.setHasReadme(true);

        when(analyzer.analyze(purl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(model));

        final var arg = ResolvePackageHealthMetadataActivityArg.newBuilder()
                .addPurls(purl.toString())
                .build();

        activity.execute(mock(ActivityContext.class), arg);

        model.setStars(101L);
        activity.execute(mock(ActivityContext.class), arg);

        final var persisted = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(packagePurl));

        assertThat(persisted).isNotNull();
        assertThat(persisted.purl()).isEqualTo(packagePurl);
        assertThat(persisted.stars()).isEqualTo(101L);
        assertThat(persisted.hasReadme()).isTrue();
        assertThat(persisted.status()).isEqualTo(PackageHealthMetadataStatus.PROCESSED);
        assertThat(persisted.lastFetch()).isEqualTo(NOW);
    }

    @Test
    void shouldPersistNotAvailableMetadata() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var packagePurl = new PackageURL("pkg:npm/example");

        createPackageMetadata(packagePurl);

        when(analyzer.analyze(purl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.NotAvailable());

        final var arg = ResolvePackageHealthMetadataActivityArg.newBuilder()
                .addPurls(purl.toString())
                .build();

        activity.execute(mock(ActivityContext.class), arg);

        final var persisted = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(packagePurl));

        assertThat(persisted).isNotNull();
        assertThat(persisted.purl()).isEqualTo(packagePurl);
        assertThat(persisted.status()).isEqualTo(PackageHealthMetadataStatus.NOT_AVAILABLE);
        assertThat(persisted.lastFetch()).isEqualTo(NOW);

        assertThat(persisted.stars()).isNull();
        assertThat(persisted.scorecardChecks()).isEmpty();
    }

    @Test
    void shouldIgnoreNullArgument() throws Exception {
        activity.execute(mock(ActivityContext.class), null);

        verifyNoInteractions(analyzer);
    }

    @Test
    void shouldIgnoreEmptyPurlList() throws Exception {
        final var arg = ResolvePackageHealthMetadataActivityArg.newBuilder().build();

        activity.execute(mock(ActivityContext.class), arg);

        verifyNoInteractions(analyzer);
    }

    @Test
    void shouldProcessMultiplePurls() throws Exception {
        final var npmPurl = new PackageURL("pkg:npm/example@1.0.0");
        final var npmPackagePurl = new PackageURL("pkg:npm/example");

        final var pypiPurl = new PackageURL("pkg:pypi/requests@2.32.0");
        final var pypiPackagePurl = new PackageURL("pkg:pypi/requests");

        createPackageMetadata(npmPackagePurl);
        createPackageMetadata(pypiPackagePurl);

        final var npmModel = new AnalyzedPackageHealth(npmPackagePurl);
        npmModel.setStars(100L);

        when(analyzer.analyze(npmPurl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(npmModel));

        when(analyzer.analyze(pypiPurl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.NotAvailable());

        final var arg = ResolvePackageHealthMetadataActivityArg.newBuilder()
                .addPurls(npmPurl.toString())
                .addPurls(pypiPurl.toString())
                .build();

        activity.execute(mock(ActivityContext.class), arg);

        final var npmMetadata = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(npmPackagePurl));

        final var pypiMetadata = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(pypiPackagePurl));

        assertThat(npmMetadata).isNotNull();
        assertThat(npmMetadata.status()).isEqualTo(PackageHealthMetadataStatus.PROCESSED);
        assertThat(npmMetadata.stars()).isEqualTo(100L);

        assertThat(pypiMetadata).isNotNull();
        assertThat(pypiMetadata.status()).isEqualTo(PackageHealthMetadataStatus.NOT_AVAILABLE);

        verify(analyzer).analyze(npmPurl);
        verify(analyzer).analyze(pypiPurl);
    }

    @Test
    void shouldRecordFailedPackageAndStoreTheRest() throws Exception {
        final var failedPurl = new PackageURL("pkg:npm/failed@1.0.0");
        final var failedPackagePurl = new PackageURL("pkg:npm/failed");
        final var fetchedPurl = new PackageURL("pkg:npm/fetched@1.0.0");
        final var fetchedPackagePurl = new PackageURL("pkg:npm/fetched");
        createPackageMetadata(failedPackagePurl);
        createPackageMetadata(fetchedPackagePurl);

        final var model = new AnalyzedPackageHealth(fetchedPackagePurl);
        model.setStars(10L);
        when(analyzer.analyze(failedPurl))
                .thenThrow(new PackageHealthAnalyzer.AnalysisException(
                        "Analysis failed", new IOException("deps.dev unavailable")));
        when(analyzer.analyze(fetchedPurl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(model));

        final var result = activity.execute(
                mock(ActivityContext.class),
                ResolvePackageHealthMetadataActivityArg.newBuilder()
                        .addPurls(failedPurl.toString())
                        .addPurls(fetchedPurl.toString())
                        .build());

        assertThat(result.getUnresolvedPurlsList()).isEmpty();
        // Recorded with a fetch time, so that the next hourly run does not select it again.
        final var failed = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(failedPackagePurl));
        assertThat(failed).isNotNull();
        assertThat(failed.status()).isEqualTo(PackageHealthMetadataStatus.NOT_AVAILABLE);
        assertThat(failed.lastFetch()).isEqualTo(NOW);
        final var fetched = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(fetchedPackagePurl));
        assertThat(fetched).isNotNull();
        assertThat(fetched.stars()).isEqualTo(10L);
    }

    @Test
    void shouldKeepStoredValuesWhenRefreshFails() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var packagePurl = new PackageURL("pkg:npm/example");
        createPackageMetadata(packagePurl);

        final Instant previousFetch = NOW.minus(Duration.ofDays(1));
        final var stored = new AnalyzedPackageHealth(packagePurl);
        stored.setStars(100L);
        withJdbiHandle(handle -> {
            new PackageHealthMetadataDao(handle)
                    .upsertAll(List.of(stored.toMetadata(PackageHealthMetadataStatus.PROCESSED, previousFetch)));
            return null;
        });

        when(analyzer.analyze(purl))
                .thenThrow(new PackageHealthAnalyzer.AnalysisException(
                        "Analysis failed", new IOException("deps.dev unavailable")));

        activity.execute(
                mock(ActivityContext.class),
                ResolvePackageHealthMetadataActivityArg.newBuilder()
                        .addPurls(purl.toString())
                        .build());

        // A failure must not clear stored values.
        final var persisted = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(packagePurl));
        assertThat(persisted).isNotNull();
        assertThat(persisted.status()).isEqualTo(PackageHealthMetadataStatus.PROCESSED);
        assertThat(persisted.stars()).isEqualTo(100L);
        assertThat(persisted.lastFetch()).isEqualTo(NOW);
    }

    @Test
    void shouldStoreFetchedPackagesAndReturnRestWhenRateLimitIsReached() throws Exception {
        final var fetchedPurl = new PackageURL("pkg:npm/fetched@1.0.0");
        final var fetchedPackagePurl = new PackageURL("pkg:npm/fetched");
        final var limitedPurl = new PackageURL("pkg:npm/limited@1.0.0");
        final var laterPurl = new PackageURL("pkg:npm/later@1.0.0");
        createPackageMetadata(fetchedPackagePurl);
        final var resetAt = NOW.plus(Duration.ofMinutes(10));

        final var model = new AnalyzedPackageHealth(fetchedPackagePurl);
        model.setStars(10L);
        when(analyzer.analyze(fetchedPurl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(model));
        when(analyzer.analyze(limitedPurl))
                .thenThrow(new PackageHealthAnalyzer.AnalysisException(
                        "GitHub request failed", new ApiRateLimitException(resetAt)));

        final var result = activity.execute(
                mock(ActivityContext.class),
                ResolvePackageHealthMetadataActivityArg.newBuilder()
                        .addPurls(fetchedPurl.toString())
                        .addPurls(limitedPurl.toString())
                        .addPurls(laterPurl.toString())
                        .build());

        assertThat(result.getUnresolvedPurlsList()).containsExactly(limitedPurl.toString(), laterPurl.toString());
        assertThat(Timestamps.toMillis(result.getRateLimitResetAt())).isEqualTo(resetAt.toEpochMilli());
        final var stored = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(fetchedPackagePurl));
        assertThat(stored).isNotNull();
        verify(analyzer, never()).analyze(laterPurl);
    }

    @Test
    void shouldStoreDepsDevDataAndKeepStoredGitHubDataWhenGitHubFails() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var packagePurl = new PackageURL("pkg:npm/example");
        final var repository = "github.com/acme/example";
        createPackageMetadata(packagePurl);

        final var stored = new AnalyzedPackageHealth(packagePurl);
        stored.setStars(100L);
        stored.setOpenIssues(7L);
        stored.setContributors(5L);
        stored.setRepositoryArchived(true);
        storeHealth(stored, NOW.minus(Duration.ofDays(1)));

        final var depsDevPart = new AnalyzedPackageHealth(packagePurl);
        depsDevPart.setStars(200L);
        depsDevPart.setOpenIssues(9L);
        depsDevPart.setScorecardScore(7.0f);
        when(analyzer.analyze(purl))
                .thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(depsDevPart, repository));
        when(analyzer.analyzeGitHubRepository(packagePurl, repository))
                .thenThrow(new PackageHealthAnalyzer.AnalysisException(
                        "GitHub analysis failed", new IOException("GitHub unavailable")));

        final var result = activity.execute(
                mock(ActivityContext.class),
                ResolvePackageHealthMetadataActivityArg.newBuilder()
                        .addPurls(purl.toString())
                        .build());

        assertThat(result.getUnresolvedPurlsList()).isEmpty();
        assertThat(result.getPendingGithubFetchesList()).isEmpty();
        final var persisted = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(packagePurl));
        assertThat(persisted).isNotNull();
        assertThat(persisted.stars()).isEqualTo(200L);
        assertThat(persisted.scorecardScore()).isEqualTo(7.0f);
        assertThat(persisted.openIssues()).isEqualTo(7L);
        assertThat(persisted.contributors()).isEqualTo(5L);
        assertThat(persisted.repositoryArchived()).isTrue();
        assertThat(persisted.lastFetch()).isEqualTo(NOW);
    }

    @Test
    void shouldKeepFetchingDepsDevAndReturnPendingGitHubFetchesWhenGitHubRateLimitIsReached() throws Exception {
        final var limitedPurl = new PackageURL("pkg:npm/limited@1.0.0");
        final var limitedPackagePurl = new PackageURL("pkg:npm/limited");
        final var laterPurl = new PackageURL("pkg:npm/later@1.0.0");
        final var laterPackagePurl = new PackageURL("pkg:npm/later");
        createPackageMetadata(limitedPackagePurl);
        createPackageMetadata(laterPackagePurl);
        final var resetAt = NOW.plus(Duration.ofMinutes(30));

        final var limitedModel = new AnalyzedPackageHealth(limitedPackagePurl);
        limitedModel.setStars(10L);
        final var laterModel = new AnalyzedPackageHealth(laterPackagePurl);
        laterModel.setStars(20L);
        when(analyzer.analyze(limitedPurl))
                .thenReturn(
                        new PackageHealthAnalyzer.AnalysisResult.Available(limitedModel, "github.com/acme/limited"));
        when(analyzer.analyze(laterPurl))
                .thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(laterModel, "github.com/acme/later"));
        when(analyzer.analyzeGitHubRepository(limitedPackagePurl, "github.com/acme/limited"))
                .thenThrow(new PackageHealthAnalyzer.AnalysisException(
                        "GitHub analysis failed", new ApiRateLimitException(resetAt)));

        final var result = activity.execute(
                mock(ActivityContext.class),
                ResolvePackageHealthMetadataActivityArg.newBuilder()
                        .addPurls(limitedPurl.toString())
                        .addPurls(laterPurl.toString())
                        .build());

        assertThat(result.getUnresolvedPurlsList()).isEmpty();
        assertThat(result.getPendingGithubFetchesList())
                .extracting(PackageHealthGitHubFetch::getPurl, PackageHealthGitHubFetch::getRepository)
                .containsExactly(
                        tuple(limitedPackagePurl.canonicalize(), "github.com/acme/limited"),
                        tuple(laterPackagePurl.canonicalize(), "github.com/acme/later"));
        assertThat(Timestamps.toMillis(result.getRateLimitResetAt())).isEqualTo(resetAt.toEpochMilli());
        verify(analyzer, never()).analyzeGitHubRepository(laterPackagePurl, "github.com/acme/later");

        final var later = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(laterPackagePurl));
        assertThat(later).isNotNull();
        assertThat(later.stars()).isEqualTo(20L);
    }

    @Test
    void shouldAddGitHubDataToStoredPackageWithoutCallingDepsDev() throws Exception {
        final var packagePurl = new PackageURL("pkg:npm/example");
        final var repository = "github.com/acme/example";
        createPackageMetadata(packagePurl);

        final Instant depsDevFetch = NOW.minus(Duration.ofMinutes(30));
        final var stored = new AnalyzedPackageHealth(packagePurl);
        stored.setStars(100L);
        stored.setScorecardScore(8.0f);
        stored.setScorecardChecks(List.of(
                new PackageHealthScorecardCheck(packagePurl, "Maintained", null, 10.0f, null, List.of(), null)));
        storeHealth(stored, depsDevFetch);

        final var gitHubPart = new AnalyzedPackageHealth(packagePurl);
        gitHubPart.setContributors(12L);
        gitHubPart.setRepositoryArchived(true);
        when(analyzer.analyzeGitHubRepository(packagePurl, repository)).thenReturn(Optional.of(gitHubPart));

        activity.execute(
                mock(ActivityContext.class),
                ResolvePackageHealthMetadataActivityArg.newBuilder()
                        .addGithubFetches(PackageHealthGitHubFetch.newBuilder()
                                .setPurl(packagePurl.canonicalize())
                                .setRepository(repository))
                        .build());

        verify(analyzer, never()).analyze(any());
        final var persisted = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(packagePurl));
        assertThat(persisted).isNotNull();
        assertThat(persisted.stars()).isEqualTo(100L);
        assertThat(persisted.scorecardScore()).isEqualTo(8.0f);
        assertThat(persisted.scorecardChecks())
                .extracting(PackageHealthScorecardCheck::name)
                .containsExactly("Maintained");
        assertThat(persisted.contributors()).isEqualTo(12L);
        assertThat(persisted.repositoryArchived()).isTrue();
        assertThat(persisted.lastFetch()).isEqualTo(depsDevFetch);
    }

    @Test
    void shouldNotCallExternalApisWhenDisabled() throws Exception {
        qm.createConfigProperty(
                PACKAGE_HEALTH_RESOLUTION_ENABLED.getGroupName(),
                PACKAGE_HEALTH_RESOLUTION_ENABLED.getPropertyName(),
                "false",
                PACKAGE_HEALTH_RESOLUTION_ENABLED.getPropertyType(),
                PACKAGE_HEALTH_RESOLUTION_ENABLED.getDescription());

        final var result = activity.execute(
                mock(ActivityContext.class),
                ResolvePackageHealthMetadataActivityArg.newBuilder()
                        .addPurls("pkg:npm/example@1.0.0")
                        .build());

        assertThat(result.getUnresolvedPurlsList()).isEmpty();
        verifyNoInteractions(analyzer);
    }

    private static void createPackageMetadata(final PackageURL packagePurl) {
        withJdbiHandle(handle -> new PackageMetadataDao(handle)
                .upsertAll(List.of(new PackageMetadata(packagePurl, "1.0.0", null, NOW, "test", "test"))));
    }

    private static void storeHealth(final AnalyzedPackageHealth health, final Instant fetchedAt) {
        withJdbiHandle(handle -> {
            new PackageHealthMetadataDao(handle)
                    .upsertAll(List.of(health.toMetadata(PackageHealthMetadataStatus.PROCESSED, fetchedAt)));
            return null;
        });
    }
}
