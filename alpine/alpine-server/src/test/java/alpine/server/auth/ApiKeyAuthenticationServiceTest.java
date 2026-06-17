/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.server.auth;

import alpine.model.ApiKey;
import alpine.model.Team;
import alpine.persistence.AlpineQueryManager;
import alpine.security.ApiKeyDecoder;
import alpine.security.ApiKeyGenerator;
import alpine.server.persistence.PersistenceManagerFactory;
import org.glassfish.jersey.server.ContainerRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.naming.AuthenticationException;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ApiKeyAuthenticationServiceTest {

    @AfterEach
    public void tearDown() {
        PersistenceManagerFactory.tearDown();
    }

    @Test
    public void authenticationWorksWithRightKey() throws AuthenticationException {
        ApiKey apiKey;
        try (final AlpineQueryManager qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            apiKey = qm.createApiKey(team);
        }
        final ContainerRequest containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(apiKey.getKey());
        final ApiKeyAuthenticationService authService = new ApiKeyAuthenticationService(containerRequestMock);

        final ApiKey authenticatedUser = (ApiKey) authService.authenticate();
        assertThat(authenticatedUser).isNotNull();
        assertThat(authenticatedUser.getId()).isEqualTo(apiKey.getId());
    }

    @Test
    void shouldAuthenticateWithDifferentPrefix() throws AuthenticationException {
        final ApiKey apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final Team team = qm.createTeam("Test");
            apiKey = qm.createApiKey(team);
        }

        final String keyWithDifferentPrefix = apiKey.getKey().replaceFirst("^alpine_", "foobar_");
        assertThat(keyWithDifferentPrefix).startsWith("foobar_"); // Sanity check that replacement worked.

        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(keyWithDifferentPrefix);
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        final var authenticatedApiKey = (ApiKey) authService.authenticate();
        assertThat(authenticatedApiKey).isNotNull();
        assertThat(authenticatedApiKey.getId()).isEqualTo(apiKey.getId());
    }

    @Test
    public void authenticationWorksWithRegeneratedKey() throws AuthenticationException {
        ApiKey apiKey;
        try (final AlpineQueryManager qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            var originalApiKey = qm.createApiKey(team);
            apiKey = qm.regenerateApiKey(originalApiKey);
        }
        final ContainerRequest containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(apiKey.getKey());
        final ApiKeyAuthenticationService authService = new ApiKeyAuthenticationService(containerRequestMock);

        final ApiKey authenticatedUser = (ApiKey) authService.authenticate();
        assertThat(authenticatedUser).isNotNull();
        assertThat(authenticatedUser.getId()).isEqualTo(apiKey.getId());
    }

    @Test
    public void shouldAuthenticateWithLegacyApiKey() throws AuthenticationException {
        final ApiKey apiKey = createLegacyApiKey(/* withPrefix */ false);

        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(apiKey.getKey());
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        final var authenticatedApiKey = (ApiKey) authService.authenticate();
        assertThat(authenticatedApiKey).isNotNull();
        assertThat(authenticatedApiKey.getId()).isEqualTo(apiKey.getId());
    }

    @Test
    public void shouldAuthenticateWithLegacyApiKeyWithPrefix() throws AuthenticationException {
        final ApiKey apiKey = createLegacyApiKey(/* withPrefix */ true);

        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(apiKey.getKey());
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        final var authenticatedApiKey = (ApiKey) authService.authenticate();
        assertThat(authenticatedApiKey).isNotNull();
        assertThat(authenticatedApiKey.getId()).isEqualTo(apiKey.getId());
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForOldKeyAfterRegeneration() {
        ApiKey apiKey;
        String oldKey;
        try (final AlpineQueryManager qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            apiKey = qm.createApiKey(team);
            oldKey = apiKey.getKey();
            qm.regenerateApiKey(apiKey);
        }
        final ContainerRequest containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(oldKey);
        final ApiKeyAuthenticationService authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class)
                .isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForInvalidKey() {
        ApiKey apiKey;
        try (final AlpineQueryManager qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            apiKey = qm.createApiKey(team);
        }
        final ContainerRequest containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(ApiKey.PREFIX + apiKey.getPublicId() + "0".repeat(ApiKey.API_KEY_LENGTH - ApiKey.LEGACY_PUBLIC_ID_LENGTH));
        final ApiKeyAuthenticationService authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class)
                .isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForInvalidPrefix() {
        ApiKey apiKey;
        try (final AlpineQueryManager qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            apiKey = qm.createApiKey(team);
        }
        final ContainerRequest containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(ApiKey.PREFIX + "0".repeat(ApiKey.LEGACY_PUBLIC_ID_LENGTH) + apiKey.getSecret());
        final ApiKeyAuthenticationService authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class)
                .isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForToShortKey() {
        try (final AlpineQueryManager qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            qm.createApiKey(team);
        }
        final ContainerRequest containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn("InvalidKey");
        final ApiKeyAuthenticationService authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class)
                .isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForToLongKey() {
        ApiKey apiKey;
        try (final AlpineQueryManager qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            apiKey = qm.createApiKey(team);
        }
        final ContainerRequest containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(apiKey.getKey() + "1");
        final ApiKeyAuthenticationService authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class)
                .isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForInvalidKeyForLegacy() {
        final var apiKey = createLegacyApiKey(true);
        final ContainerRequest containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(ApiKey.PREFIX + apiKey.getPublicId() + "0".repeat(ApiKey.API_KEY_LENGTH - ApiKey.LEGACY_PUBLIC_ID_LENGTH));
        final ApiKeyAuthenticationService authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class)
                .isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForInvalidPrefixForLegacy() {
        final var apiKey = createLegacyApiKey(true);
        final ContainerRequest containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(ApiKey.PREFIX + "0".repeat(ApiKey.LEGACY_PUBLIC_ID_LENGTH) + apiKey.getSecret());
        final ApiKeyAuthenticationService authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class)
                .isThrownBy(authService::authenticate);
    }

    private ApiKey createLegacyApiKey(final boolean withPrefix) {
        String rawKey = ApiKeyGenerator.generateSecret(ApiKey.API_KEY_LENGTH);
        if (withPrefix) {
            rawKey = "alpine_" + rawKey;
        }

        final ApiKey decodedApiKey = ApiKeyDecoder.decode(rawKey);

        try (final AlpineQueryManager qm = new AlpineQueryManager()) {
            final Team team = qm.createTeam("Test");

            final var apiKey = new ApiKey();
            apiKey.setPublicId(decodedApiKey.getPublicId());
            apiKey.setKey(decodedApiKey.getKey());
            apiKey.setSecret(decodedApiKey.getSecret());
            apiKey.setSecretHash(decodedApiKey.getSecretHash());
            apiKey.setCreated(new Date());
            apiKey.setTeams(List.of(team));
            return qm.persist(apiKey);
        }
    }
}
