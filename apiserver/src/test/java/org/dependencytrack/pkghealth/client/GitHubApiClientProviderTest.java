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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.secret.management.SecretManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class GitHubApiClientProviderTest extends PersistenceCapableTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    private SecretManager secretManager;
    private Clock clock;
    private GitHubApiClientProvider provider;

    @BeforeEach
    void setUp() {
        secretManager = mock(SecretManager.class);
        clock = mock(Clock.class);
        when(clock.instant()).thenReturn(NOW);
        provider = new GitHubApiClientProvider(secretManager, clock);
    }

    @Test
    void shouldReturnEmptyWhenNoGitHubRepositoryIsConfigured() {
        final var result = provider.get();

        assertThat(result).isEmpty();
        verifyNoInteractions(secretManager);
    }

    @Test
    void shouldReturnEmptyWhenGitHubRepositoryIsDisabled() {
        createGitHubRepository(false, true, "github-token-reference");

        final var result = provider.get();

        assertThat(result).isEmpty();
        verifyNoInteractions(secretManager);
    }

    @Test
    void shouldReturnEmptyWhenAuthenticationIsDisabled() {
        createGitHubRepository(true, false, null);

        final var result = provider.get();

        assertThat(result).isEmpty();
        verifyNoInteractions(secretManager);
    }

    @Test
    void shouldReturnEmptyWhenSecretCannotBeResolved() {
        createGitHubRepository(true, true, "github-token-reference");

        when(secretManager.getSecretValue("github-token-reference")).thenReturn(null);

        final var result = provider.get();

        assertThat(result).isEmpty();

        verify(secretManager).getSecretValue("github-token-reference");
    }

    @Test
    void shouldCreateClientWithResolvedToken() {
        createGitHubRepository(true, true, "github-token-reference");

        when(secretManager.getSecretValue("github-token-reference")).thenReturn("resolved-github-token");

        final var result = provider.get();

        assertThat(result).isPresent();
        assertThat(result.orElseThrow()).isInstanceOf(GitHubApiClient.class);

        verify(secretManager).getSecretValue("github-token-reference");
    }

    @Test
    void shouldResolveTokenOnceWithinResolutionTtl() {
        createGitHubRepository(true, true, "github-token-reference");
        when(secretManager.getSecretValue("github-token-reference")).thenReturn("token-1");

        final var first = provider.get().orElseThrow();
        final var second = provider.get().orElseThrow();

        assertThat(second).isSameAs(first);
        verify(secretManager, times(1)).getSecretValue("github-token-reference");
    }

    @Test
    void shouldReuseClientAcrossResolutionsUntilTokenChanges() {
        createGitHubRepository(true, true, "github-token-reference");
        when(secretManager.getSecretValue("github-token-reference")).thenReturn("token-1", "token-1", "token-2");
        when(clock.instant())
                .thenReturn(
                        NOW,
                        NOW.plus(GitHubApiClientProvider.RESOLUTION_TTL),
                        NOW.plus(GitHubApiClientProvider.RESOLUTION_TTL.multipliedBy(2)));

        final var first = provider.get().orElseThrow();
        final var second = provider.get().orElseThrow();
        final var afterRotation = provider.get().orElseThrow();

        assertThat(second).isSameAs(first);
        assertThat(afterRotation).isNotSameAs(first);
        verify(secretManager, times(3)).getSecretValue("github-token-reference");
    }

    @Test
    void shouldNotUseTokenOfGitHubEnterpriseRepository() {
        createGitHubRepository("github-enterprise", "https://github.acme.example", "enterprise-token-reference");

        final var result = provider.get();

        assertThat(result).isEmpty();
        verifyNoInteractions(secretManager);
    }

    @Test
    void shouldUseTokenOfGitHubDotComRepositoryWhenEnterpriseRepositoryComesFirst() {
        createGitHubRepository("github-enterprise", "https://github.acme.example", "enterprise-token-reference");
        createGitHubRepository("github", "https://github.com", "github-token-reference");
        when(secretManager.getSecretValue("github-token-reference")).thenReturn("resolved-github-token");

        final var result = provider.get();

        assertThat(result).isPresent();
        verify(secretManager).getSecretValue("github-token-reference");
        verify(secretManager, never()).getSecretValue("enterprise-token-reference");
    }

    private void createGitHubRepository(
            final boolean enabled, final boolean authenticationRequired, final String password) {
        qm.createRepository(
                RepositoryType.GITHUB,
                "github",
                "https://github.com",
                enabled,
                false,
                authenticationRequired,
                null,
                password);
    }

    private void createGitHubRepository(final String identifier, final String url, final String password) {
        qm.createRepository(RepositoryType.GITHUB, identifier, url, true, false, true, null, password);
    }
}
