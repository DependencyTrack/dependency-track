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
import alpine.model.auth.ApiKeyPrincipal;
import alpine.model.auth.TeamRef;
import alpine.persistence.AlpineQueryManager;
import alpine.security.ApiKeyDecoder;
import alpine.security.ApiKeyGenerator;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.testing.database.TestDatabaseExtension;
import org.glassfish.jersey.server.ContainerRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.naming.AuthenticationException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ApiKeyAuthenticationServiceTest {

    @RegisterExtension
    static final TestDatabaseExtension DATABASE = new TestDatabaseExtension();

    @Test
    public void authenticationWorksWithRightKey() throws AuthenticationException {
        ApiKey apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            apiKey = qm.createApiKey(team);
        }
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key")).thenReturn(apiKey.getKey());
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        final ApiKeyPrincipal authenticatedApiKey = authService.authenticate();
        assertThat(authenticatedApiKey).isNotNull();
        assertThat(authenticatedApiKey.id()).isEqualTo(apiKey.getId());
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
        when(containerRequestMock.getHeaderString("X-Api-Key")).thenReturn(keyWithDifferentPrefix);
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        final ApiKeyPrincipal authenticatedApiKey = authService.authenticate();
        assertThat(authenticatedApiKey).isNotNull();
        assertThat(authenticatedApiKey.id()).isEqualTo(apiKey.getId());
    }

    @Test
    public void authenticationWorksWithRegeneratedKey() throws AuthenticationException {
        ApiKey apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            var originalApiKey = qm.createApiKey(team);
            apiKey = qm.regenerateApiKey(originalApiKey);
        }
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key")).thenReturn(apiKey.getKey());
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        final ApiKeyPrincipal authenticatedApiKey = authService.authenticate();
        assertThat(authenticatedApiKey).isNotNull();
        assertThat(authenticatedApiKey.id()).isEqualTo(apiKey.getId());
    }

    @Test
    public void shouldAuthenticateWithLegacyApiKey() throws AuthenticationException {
        final ApiKey apiKey = createLegacyApiKey(/* withPrefix */ false);

        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key")).thenReturn(apiKey.getKey());
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        final ApiKeyPrincipal authenticatedApiKey = authService.authenticate();
        assertThat(authenticatedApiKey).isNotNull();
        assertThat(authenticatedApiKey.id()).isEqualTo(apiKey.getId());
    }

    @Test
    public void shouldAuthenticateWithLegacyApiKeyWithPrefix() throws AuthenticationException {
        final ApiKey apiKey = createLegacyApiKey(/* withPrefix */ true);

        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key")).thenReturn(apiKey.getKey());
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        final ApiKeyPrincipal authenticatedApiKey = authService.authenticate();
        assertThat(authenticatedApiKey).isNotNull();
        assertThat(authenticatedApiKey.id()).isEqualTo(apiKey.getId());
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForOldKeyAfterRegeneration() {
        ApiKey apiKey;
        String oldKey;
        try (final var qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            apiKey = qm.createApiKey(team);
            oldKey = apiKey.getKey();
            qm.regenerateApiKey(apiKey);
        }
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key")).thenReturn(oldKey);
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForInvalidKey() {
        ApiKey apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            apiKey = qm.createApiKey(team);
        }
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(ApiKey.PREFIX
                        + apiKey.getPublicId()
                        + "0".repeat(ApiKey.API_KEY_LENGTH - ApiKey.LEGACY_PUBLIC_ID_LENGTH));
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForInvalidPrefix() {
        ApiKey apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            apiKey = qm.createApiKey(team);
        }
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(ApiKey.PREFIX + "0".repeat(ApiKey.LEGACY_PUBLIC_ID_LENGTH) + apiKey.getSecret());
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForToShortKey() {
        try (final var qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            qm.createApiKey(team);
        }
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key")).thenReturn("InvalidKey");
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForToLongKey() {
        ApiKey apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final var team = qm.createTeam("Test");
            apiKey = qm.createApiKey(team);
        }
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key")).thenReturn(apiKey.getKey() + "1");
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForInvalidKeyForLegacy() {
        final var apiKey = createLegacyApiKey(true);
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(ApiKey.PREFIX
                        + apiKey.getPublicId()
                        + "0".repeat(ApiKey.API_KEY_LENGTH - ApiKey.LEGACY_PUBLIC_ID_LENGTH));
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticationShouldThrowAuthenticationExceptionForInvalidPrefixForLegacy() {
        final var apiKey = createLegacyApiKey(true);
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(ApiKey.PREFIX + "0".repeat(ApiKey.LEGACY_PUBLIC_ID_LENGTH) + apiKey.getSecret());
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(authService::authenticate);
    }

    private ApiKey createLegacyApiKey(final boolean withPrefix) {
        String rawKey = ApiKeyGenerator.generateSecret(ApiKey.API_KEY_LENGTH);
        if (withPrefix) {
            rawKey = "alpine_" + rawKey;
        }

        final ApiKey decodedApiKey = ApiKeyDecoder.decode(rawKey);

        try (final var qm = new AlpineQueryManager()) {
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

    @Test
    void shouldResolveTeamsAndDeduplicatedPermissionsOfAllTeams() throws Exception {
        final String rawKey;
        try (final var qm = new AlpineQueryManager()) {
            final Team bravo = qm.createTeam("bravo");
            final Team alpha = qm.createTeam("alpha");
            final var shared = qm.createPermission("SHARED_PERM", null);
            bravo.setPermissions(List.of(shared, qm.createPermission("BRAVO_PERM", null)));
            alpha.setPermissions(List.of(shared, qm.createPermission("ALPHA_PERM", null)));
            qm.persist(bravo);
            qm.persist(alpha);

            final ApiKey created = qm.createApiKey(bravo);
            created.getTeams().add(alpha);
            rawKey = created.getKey();
        }

        final ApiKeyPrincipal principal = authenticate(rawKey);

        assertThat(principal.teams()).extracting(TeamRef::name).containsExactly("alpha", "bravo");
        assertThat(principal.teams()).allSatisfy(team -> {
            assertThat(team.id()).isPositive();
            assertThat(team.uuid()).isNotNull();
        });
        assertThat(principal.effectivePermissions())
                .containsExactlyInAnyOrder("ALPHA_PERM", "BRAVO_PERM", "SHARED_PERM");
    }

    @Test
    void shouldResolvePrincipalWithoutTeams() throws Exception {
        final String rawKey;
        final long apiKeyId;
        try (final var qm = new AlpineQueryManager()) {
            final ApiKey created = qm.createApiKey(qm.createTeam("doomed"));
            rawKey = created.getKey();
            apiKeyId = created.getId();
        }
        executeUpdate(/* language=SQL */ "DELETE FROM \"APIKEYS_TEAMS\" WHERE \"APIKEY_ID\" = " + apiKeyId);

        final ApiKeyPrincipal principal = authenticate(rawKey);

        assertThat(principal.teams()).isEmpty();
        assertThat(principal.effectivePermissions()).isEmpty();
    }

    @Test
    void shouldThrowWhenNoApiKeyExistsForPublicId() {
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key"))
                .thenReturn(ApiKeyGenerator.generate("aaaaaaaa").getKey());
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);

        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(authService::authenticate);
    }

    @Test
    void shouldThrowWhenPortfolioAccessControlIsQueriedBeforeAuthenticating() {
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key")).thenReturn("whatever");

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(new ApiKeyAuthenticationService(containerRequestMock)::isPortfolioAccessControlEnabled);
    }

    @ParameterizedTest
    @CsvSource({"true,true", "TRUE,true", " true ,true", "1,true", "false,false", "0,false", "yes,false"})
    void shouldReportWhetherPortfolioAccessControlIsEnabled(String propertyValue, boolean expected) throws Exception {
        final String rawKey;
        try (final var qm = new AlpineQueryManager()) {
            rawKey = qm.createApiKey(qm.createTeam("team")).getKey();
        }
        executeUpdate(/* language=SQL */ """
            INSERT INTO "CONFIGPROPERTY" ("GROUPNAME", "PROPERTYNAME", "PROPERTYVALUE", "PROPERTYTYPE")
            VALUES ('access-management', 'acl.enabled', '%s', 'BOOLEAN')
            """.formatted(propertyValue));

        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key")).thenReturn(rawKey);
        final var authService = new ApiKeyAuthenticationService(containerRequestMock);
        authService.authenticate();

        assertThat(authService.isPortfolioAccessControlEnabled()).isEqualTo(expected);
    }

    @Test
    void shouldAuthenticateWithASingleStatement() throws Exception {
        final String rawKey;
        try (final var qm = new AlpineQueryManager()) {
            final Team team = qm.createTeam("team");
            team.setPermissions(List.of(qm.createPermission("PERM", null)));
            qm.persist(team);
            rawKey = qm.createApiKey(team).getKey();
        }

        final var statementCount = new AtomicInteger();
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key")).thenReturn(rawKey);
        final var authService = new ApiKeyAuthenticationService(
                containerRequestMock,
                CountingDataSource.wrap(DataSourceRegistry.getInstance().getDefault(), statementCount));

        assertThat(authService.authenticate()).isNotNull();
        assertThat(statementCount.get()).isEqualTo(1);
    }

    private static ApiKeyPrincipal authenticate(String key) throws AuthenticationException {
        final var containerRequestMock = mock(ContainerRequest.class);
        when(containerRequestMock.getHeaderString("X-Api-Key")).thenReturn(key);
        return new ApiKeyAuthenticationService(containerRequestMock).authenticate();
    }

    private static void executeUpdate(String sql) throws SQLException {
        try (final Connection connection =
                        DataSourceRegistry.getInstance().getDefault().getConnection();
                final Statement statement = connection.createStatement()) {
            statement.executeUpdate(sql);
        }
    }
}
