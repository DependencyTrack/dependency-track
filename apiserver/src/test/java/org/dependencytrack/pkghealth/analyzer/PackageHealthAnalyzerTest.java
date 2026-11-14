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
package org.dependencytrack.pkghealth.analyzer;

import com.github.packageurl.PackageURL;
import org.dependencytrack.pkghealth.client.DepsDevApiClient;
import org.dependencytrack.pkghealth.client.GitHubApiClient;
import org.dependencytrack.pkghealth.client.GitHubApiClientProvider;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class PackageHealthAnalyzerTest {

    private DepsDevApiClient depsDevApiClient;
    private GitHubApiClientProvider gitHubApiClientProvider;
    private PackageHealthAnalyzer analyzer;

    @BeforeEach
    void beforeEach() {
        depsDevApiClient = mock(DepsDevApiClient.class);
        gitHubApiClientProvider = mock(GitHubApiClientProvider.class);

        analyzer = new PackageHealthAnalyzer(depsDevApiClient, gitHubApiClientProvider);
    }

    @Test
    void shouldSupportDepsDevPackageTypes() {
        assertThat(analyzer.supportedPurlTypes())
                .containsExactlyInAnyOrder("npm", "golang", "maven", "pypi", "nuget", "cargo", "gem");
    }

    @Test
    void shouldReturnNotAvailableForUnsupportedPackageType() throws Exception {
        final var purl = new PackageURL("pkg:docker/library/nginx@1.27");

        assertThat(analyzer.analyze(purl)).isInstanceOf(PackageHealthAnalyzer.AnalysisResult.NotAvailable.class);

        verifyNoInteractions(depsDevApiClient, gitHubApiClientProvider);
    }

    @Test
    void shouldReturnNotAvailableWhenLatestVersionIsMissing() throws Exception {
        final var purl = new PackageURL("pkg:npm/lodash@4.17.21");

        when(depsDevApiClient.fetchLatestVersion("NPM", "lodash")).thenReturn(Optional.empty());

        final var result = analyzer.analyze(purl);

        assertThat(result).isInstanceOf(PackageHealthAnalyzer.AnalysisResult.NotAvailable.class);

        verify(depsDevApiClient).fetchLatestVersion("NPM", "lodash");
        verifyNoInteractions(gitHubApiClientProvider);
    }

    @Test
    void shouldCountDependentsOfDefaultVersion() throws Exception {
        final var purl = new PackageURL("pkg:npm/lodash@4.17.20");

        when(depsDevApiClient.fetchLatestVersion("NPM", "lodash")).thenReturn(Optional.of("4.17.21"));

        when(depsDevApiClient.fetchDependents("NPM", "lodash", "4.17.21")).thenReturn(Optional.of(123L));

        when(depsDevApiClient.fetchSourceRepository("NPM", "lodash", "4.17.21")).thenReturn(Optional.empty());

        final var result = analyzer.analyze(purl);

        assertThat(result).isInstanceOf(PackageHealthAnalyzer.AnalysisResult.Available.class);

        final var available = (PackageHealthAnalyzer.AnalysisResult.Available) result;

        assertThat(available.metadata().getDependents()).isEqualTo(123L);

        // Health is stored per package, so the version of the PURL must not select the dependents.
        verify(depsDevApiClient, never()).fetchDependents("NPM", "lodash", "4.17.20");

        verifyNoInteractions(gitHubApiClientProvider);
    }

    @Test
    void shouldSkipGitHubClientForNonGitHubRepository() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var packagePurl = new PackageURL("pkg:npm/example");

        when(depsDevApiClient.fetchLatestVersion("NPM", "example")).thenReturn(Optional.of("1.0.0"));

        when(depsDevApiClient.fetchDependents("NPM", "example", "1.0.0")).thenReturn(Optional.of(42L));

        when(depsDevApiClient.fetchSourceRepository("NPM", "example", "1.0.0"))
                .thenReturn(Optional.of("gitlab.com/acme/example"));

        when(depsDevApiClient.fetchProjectMetadata(packagePurl, "gitlab.com/acme/example"))
                .thenReturn(Optional.empty());

        final var result = analyzer.analyze(purl);

        assertThat(result).isInstanceOf(PackageHealthAnalyzer.AnalysisResult.Available.class);

        final var available = (PackageHealthAnalyzer.AnalysisResult.Available) result;

        assertThat(available.metadata().getDependents()).isEqualTo(42L);
        assertThat(available.gitHubRepository()).isNull();

        verify(depsDevApiClient).fetchProjectMetadata(packagePurl, "gitlab.com/acme/example");

        verifyNoInteractions(gitHubApiClientProvider);
    }

    @Test
    void shouldReturnDepsDevMetadataAndGitHubRepositoryWithoutCallingGitHub() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var packagePurl = new PackageURL("pkg:npm/example");
        final var repository = "github.com/acme/example";

        final var depsDevMetadata = new AnalyzedPackageHealth(packagePurl);
        depsDevMetadata.setStars(100L);
        depsDevMetadata.setScorecardScore(8.5f);

        when(depsDevApiClient.fetchLatestVersion("NPM", "example")).thenReturn(Optional.of("1.0.0"));
        when(depsDevApiClient.packagePageUrl("NPM", "example")).thenReturn("https://deps.dev/npm/example");
        when(depsDevApiClient.fetchDependents("NPM", "example", "1.0.0")).thenReturn(Optional.of(42L));
        when(depsDevApiClient.fetchSourceRepository("NPM", "example", "1.0.0")).thenReturn(Optional.of(repository));
        when(depsDevApiClient.fetchProjectMetadata(packagePurl, repository)).thenReturn(Optional.of(depsDevMetadata));

        final var result = analyzer.analyze(purl);

        assertThat(result).isInstanceOf(PackageHealthAnalyzer.AnalysisResult.Available.class);
        final var available = (PackageHealthAnalyzer.AnalysisResult.Available) result;
        assertThat(available.gitHubRepository()).isEqualTo(repository);

        final var metadata = available.metadata();
        assertThat(metadata.getPurl()).isEqualTo(packagePurl);
        assertThat(metadata.getDependents()).isEqualTo(42L);
        assertThat(metadata.getDepsDevUrl()).isEqualTo("https://deps.dev/npm/example");
        assertThat(metadata.getGithubUrl()).isEqualTo("https://github.com/acme/example");
        assertThat(metadata.getStars()).isEqualTo(100L);
        assertThat(metadata.getScorecardScore()).isEqualTo(8.5f);
        assertThat(metadata.getContributors()).isNull();

        verifyNoInteractions(gitHubApiClientProvider);
    }

    @Test
    void shouldReturnNoGitHubPartWhenGitHubIsNotConfigured() throws Exception {
        final var packagePurl = new PackageURL("pkg:npm/example");

        when(gitHubApiClientProvider.get()).thenReturn(Optional.empty());

        assertThat(analyzer.analyzeGitHubRepository(packagePurl, "github.com/acme/example"))
                .isEmpty();
    }

    @Test
    void shouldWrapGitHubIOExceptionInAnalysisException() throws Exception {
        final var packagePurl = new PackageURL("pkg:npm/example");
        final var repository = "github.com/acme/example";

        final var gitHubApiClient = mock(GitHubApiClient.class);
        when(gitHubApiClientProvider.get()).thenReturn(Optional.of(gitHubApiClient));
        when(gitHubApiClient.fetchRepositoryMetadata(packagePurl, repository))
                .thenThrow(new IOException("GitHub unavailable"));

        assertThatExceptionOfType(PackageHealthAnalyzer.AnalysisException.class)
                .isThrownBy(() -> analyzer.analyzeGitHubRepository(packagePurl, repository))
                .withCauseInstanceOf(IOException.class);
    }

    @Test
    void shouldWrapIOExceptionInAnalysisException() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");

        when(depsDevApiClient.fetchLatestVersion("NPM", "example")).thenThrow(new IOException("deps.dev unavailable"));

        assertThatExceptionOfType(PackageHealthAnalyzer.AnalysisException.class)
                .isThrownBy(() -> analyzer.analyze(purl))
                .withCauseInstanceOf(IOException.class);
    }

    @Test
    void shouldPropagateInterruptedException() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");

        when(depsDevApiClient.fetchLatestVersion("NPM", "example"))
                .thenThrow(new InterruptedException("request interrupted"));

        assertThatExceptionOfType(InterruptedException.class).isThrownBy(() -> analyzer.analyze(purl));
    }
}
