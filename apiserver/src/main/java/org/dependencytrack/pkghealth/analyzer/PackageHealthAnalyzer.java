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
import org.dependencytrack.util.PurlUtil;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Fetches package health from deps.dev and, for repositories hosted on github.com, from the GitHub API.
 */
public final class PackageHealthAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(PackageHealthAnalyzer.class);

    private static final Map<String, String> DEPS_DEV_SYSTEM_BY_PURL_TYPE = Map.ofEntries(
            Map.entry(PackageURL.StandardTypes.NPM, "NPM"),
            Map.entry(PackageURL.StandardTypes.GOLANG, "GO"),
            Map.entry(PackageURL.StandardTypes.MAVEN, "MAVEN"),
            Map.entry(PackageURL.StandardTypes.PYPI, "PYPI"),
            Map.entry(PackageURL.StandardTypes.NUGET, "NUGET"),
            Map.entry(PackageURL.StandardTypes.CARGO, "CARGO"),
            Map.entry(PackageURL.StandardTypes.GEM, "RUBYGEMS"));

    private static final Set<String> SYSTEMS_WITH_DEPENDENTS = Set.of("NPM", "CARGO", "MAVEN", "PYPI");

    private final DepsDevApiClient depsDevClient;
    private final GitHubApiClientProvider gitHubClientProvider;

    public PackageHealthAnalyzer(
            final DepsDevApiClient depsDevClient, final GitHubApiClientProvider gitHubClientProvider) {
        this.depsDevClient = Objects.requireNonNull(depsDevClient);
        this.gitHubClientProvider = Objects.requireNonNull(gitHubClientProvider);
    }

    /**
     * @return PURL types that {@link #analyze(PackageURL)} can return health metadata for
     */
    public Set<String> supportedPurlTypes() {
        return DEPS_DEV_SYSTEM_BY_PURL_TYPE.keySet();
    }

    /**
     * Fetches the deps.dev part of the health of a package. When the source repository is hosted on
     * github.com, the result names it, and {@link #analyzeGitHubRepository(PackageURL, String)}
     * fetches the rest. The two are separate so that a GitHub failure or rate limit does not
     * discard the deps.dev data.
     *
     * @return {@link AnalysisResult.NotAvailable} for PURL types outside {@link #supportedPurlTypes()}
     */
    public AnalysisResult analyze(final PackageURL purl) throws AnalysisException, InterruptedException {

        final PackageURL packagePurl =
                Objects.requireNonNull(PurlUtil.silentPurlPackageOnly(purl), "Unable to create package-only PURL");

        final var metadata = new AnalyzedPackageHealth(packagePurl);

        final String system = DEPS_DEV_SYSTEM_BY_PURL_TYPE.get(purl.getType());
        if (system == null) {
            return new AnalysisResult.NotAvailable();
        }
        final String name = toDepsDevPackageName(purl);
        metadata.setDepsDevUrl(depsDevClient.packagePageUrl(system, name));

        /*
         * We fetch package health metadata through a combination of deps.dev and the GitHub API.
         *
         * First, we retrieve the default package version from deps.dev. Health is stored per package, not per
         * version, so dependents are counted for the default version.
         *
         * The default version is then used to determine the source repository. Project metadata, including OpenSSF
         * Scorecard data, is retrieved from deps.dev. For repositories hosted on GitHub, the caller fetches the
         * remaining metadata through analyzeGitHubRepository.
         *
         * For projects not hosted on GitHub, only the metadata available through deps.dev can currently be retrieved.
         */

        try {
            final Optional<String> latestVersion = depsDevClient.fetchLatestVersion(system, name);

            if (latestVersion.isEmpty()) {
                LOGGER.debug("Could not determine latest version for {}", packagePurl);
                return new AnalysisResult.NotAvailable();
            }

            fetchDependents(metadata, system, name, latestVersion.get());

            final Optional<String> sourceRepository =
                    depsDevClient.fetchSourceRepository(system, name, latestVersion.get());

            if (sourceRepository.isEmpty()) {
                LOGGER.debug("Could not determine source repository for {}", packagePurl);
                return new AnalysisResult.Available(metadata);
            }

            final String repository = sourceRepository.get();

            depsDevClient.fetchProjectMetadata(packagePurl, repository).ifPresent(metadata::mergeFrom);

            if (!isGitHubRepository(repository)) {
                LOGGER.debug("Source repository for {} is not hosted on GitHub", packagePurl);
                return new AnalysisResult.Available(metadata);
            }

            metadata.setGithubUrl(GitHubApiClient.repositoryPageUrl(repository));

            return new AnalysisResult.Available(metadata, repository);
        } catch (IOException e) {
            throw new AnalysisException("Package health analysis failed for " + packagePurl, e);
        }
    }

    /**
     * Fetches the GitHub part of the health of a package.
     *
     * @param packagePurl Package URL without version, qualifiers, or subpath
     * @param repository  Repository as returned by {@link AnalysisResult.Available#gitHubRepository()}
     * @return Empty when GitHub is not configured or does not know the repository
     */
    public Optional<AnalyzedPackageHealth> analyzeGitHubRepository(
            final PackageURL packagePurl, final String repository) throws AnalysisException, InterruptedException {
        final Optional<GitHubApiClient> gitHubClient = gitHubClientProvider.get();
        if (gitHubClient.isEmpty()) {
            LOGGER.debug("GitHub metadata analysis is not configured");
            return Optional.empty();
        }

        try {
            return gitHubClient.get().fetchRepositoryMetadata(packagePurl, repository);
        } catch (IOException e) {
            throw new AnalysisException("GitHub analysis failed for " + packagePurl, e);
        }
    }

    private void fetchDependents(
            final AnalyzedPackageHealth metadata, final String system, final String name, final String version)
            throws IOException, InterruptedException {
        if (!SYSTEMS_WITH_DEPENDENTS.contains(system)) {
            return;
        }

        depsDevClient.fetchDependents(system, name, version).ifPresent(metadata::setDependents);
    }

    private static String toDepsDevPackageName(final PackageURL purl) {
        final String namespace = purl.getNamespace();

        if (namespace == null || namespace.isBlank()) {
            return purl.getName();
        }

        /*
           deps.dev identifies Maven packages as groupId:artifactId, while the PURL stores them separately as namespace
           and name.
        */
        if (PackageURL.StandardTypes.MAVEN.equals(purl.getType())) {
            return namespace + ":" + purl.getName();
        }

        return namespace + "/" + purl.getName();
    }

    private static boolean isGitHubRepository(final String repository) {
        return repository.toLowerCase(Locale.ROOT).startsWith("github.com/");
    }

    public sealed interface AnalysisResult {

        /**
         * @param gitHubRepository Source repository, if it is hosted on github.com, for example github.com/owner/repo
         */
        record Available(
                AnalyzedPackageHealth metadata, @Nullable String gitHubRepository) implements AnalysisResult {

            public Available(final AnalyzedPackageHealth metadata) {
                this(metadata, null);
            }
        }

        record NotAvailable() implements AnalysisResult {}
    }

    public static final class AnalysisException extends Exception {

        public AnalysisException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
