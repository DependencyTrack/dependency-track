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
package org.dependencytrack.pkghealth.client;

import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.jdbi.RepositoryDao;
import org.dependencytrack.persistence.jdbi.RepositoryDao.EnabledRepository;
import org.dependencytrack.secret.management.SecretManager;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public final class GitHubApiClientProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(GitHubApiClientProvider.class);

    /**
     * How long a resolved client, or the absence of one, is reused before the
     * repository configuration and token are looked up again.
     */
    static final Duration RESOLUTION_TTL = Duration.ofMinutes(1);

    private final SecretManager secretManager;
    private final Clock clock;

    private volatile @Nullable Resolution resolution;

    public GitHubApiClientProvider(final SecretManager secretManager) {
        this(secretManager, Clock.systemUTC());
    }

    GitHubApiClientProvider(final SecretManager secretManager, final Clock clock) {
        this.secretManager = Objects.requireNonNull(secretManager);
        this.clock = Objects.requireNonNull(clock);
    }

    public Optional<GitHubApiClient> get() {
        final Instant now = clock.instant();

        Resolution current = resolution;
        if (current != null && current.isFresh(now)) {
            return Optional.ofNullable(current.client());
        }

        synchronized (this) {
            current = resolution;
            if (current != null && current.isFresh(now)) {
                return Optional.ofNullable(current.client());
            }

            final String accessToken = resolveAccessToken();
            final GitHubApiClient previousClient = current != null ? current.client() : null;
            final GitHubApiClient client;
            if (accessToken == null) {
                client = null;
            } else if (current != null && previousClient != null && accessToken.equals(current.accessToken())) {
                // Keep the client, and the repository metadata it caches, while the token is unchanged.
                client = previousClient;
            } else {
                client = new GitHubApiClient(accessToken);
            }

            resolution = new Resolution(now, accessToken, client);
            return Optional.ofNullable(client);
        }
    }

    private @Nullable String resolveAccessToken() {
        // Requests only go to api.github.com, so tokens of GitHub Enterprise servers must not be sent.
        final Optional<EnabledRepository> repository =
                withJdbiHandle(handle ->
                                handle.attach(RepositoryDao.class).getEnabledRepositories(RepositoryType.GITHUB))
                        .stream()
                        .filter(EnabledRepository::authenticationRequired)
                        .filter(GitHubApiClientProvider::isGitHubDotCom)
                        .findFirst();

        if (repository.isEmpty()) {
            LOGGER.debug("No authenticated github.com repository is configured");
            return null;
        }

        final String secretReference = repository.get().password();

        if (secretReference == null || secretReference.isBlank()) {
            LOGGER.warn("GitHub authentication is enabled, but no token is configured");
            return null;
        }

        final String accessToken = secretManager.getSecretValue(secretReference);

        if (accessToken == null || accessToken.isBlank()) {
            LOGGER.warn("Configured GitHub token could not be resolved");
            return null;
        }

        return accessToken;
    }

    private static boolean isGitHubDotCom(final EnabledRepository repository) {
        final String host;
        try {
            host = URI.create(repository.url()).getHost();
        } catch (IllegalArgumentException e) {
            return false;
        }
        return "github.com".equalsIgnoreCase(host) || "api.github.com".equalsIgnoreCase(host);
    }

    private record Resolution(
            Instant resolvedAt,
            @Nullable String accessToken,
            @Nullable GitHubApiClient client) {

        private boolean isFresh(final Instant now) {
            return now.isBefore(resolvedAt.plus(RESOLUTION_TTL));
        }
    }
}
