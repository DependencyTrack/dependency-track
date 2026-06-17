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

import alpine.config.AlpineConfigKeys;
import alpine.model.MappedOidcGroup;
import alpine.model.OidcGroup;
import alpine.model.OidcUser;
import alpine.model.Team;
import alpine.persistence.AlpineQueryManager;
import alpine.server.persistence.PersistenceManagerFactory;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import io.smallrye.config.SmallRyeConfigBuilder;
import net.minidev.json.JSONObject;
import org.assertj.core.api.Assertions;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class OidcAuthenticationServiceTest {

    private static final String USERNAME_CLAIM_NAME = "username";
    private static final String ID_TOKEN = "idToken";
    private static final String ACCESS_TOKEN = "accessToken";

    private OidcConfiguration oidcConfigurationMock;
    private OidcIdTokenAuthenticator idTokenAuthenticatorMock;
    private OidcUserInfoAuthenticator userInfoAuthenticatorMock;

    @BeforeEach
    public void setUp() {
        oidcConfigurationMock = Mockito.mock(OidcConfiguration.class);
        idTokenAuthenticatorMock = Mockito.mock(OidcIdTokenAuthenticator.class);
        userInfoAuthenticatorMock = Mockito.mock(OidcUserInfoAuthenticator.class);
    }

    @AfterEach
    public void tearDown() {
        PersistenceManagerFactory.tearDown();
    }

    /**
     * Builds a {@link Config} with sensible defaults for OIDC tests, applying the given overrides on top.
     * Pass an empty string value to make a property appear unset (per MP Config spec, empty string converts
     * to {@link java.util.Optional#empty()} for {@code getOptionalValue}).
     */
    private static Config configWith(final Map<String, String> overrides) {
        final var values = new HashMap<String, String>();
        values.put(AlpineConfigKeys.OIDC_AUTH_CUSTOMIZER, DefaultOidcAuthenticationCustomizer.class.getName());
        values.put(AlpineConfigKeys.OIDC_USERNAME_CLAIM, USERNAME_CLAIM_NAME);
        values.put(AlpineConfigKeys.OIDC_ENABLED, "true");
        values.put(AlpineConfigKeys.OIDC_USER_PROVISIONING, "false");
        values.put(AlpineConfigKeys.OIDC_TEAM_SYNCHRONIZATION, "false");
        values.putAll(overrides);
        return new SmallRyeConfigBuilder().withDefaultValues(values).build();
    }

    private static Config defaultConfig() {
        return configWith(Map.of());
    }

    @Test
    public void isSpecifiedShouldReturnFalseWhenOidcIsDisabled() {
        final Config config = configWith(Map.of(AlpineConfigKeys.OIDC_ENABLED, "false"));

        final var authService = new OidcAuthenticationService(config, oidcConfigurationMock, ID_TOKEN, ACCESS_TOKEN);

        assertThat(authService.isSpecified()).isFalse();
    }

    @Test
    public void isSpecifiedShouldReturnFalseWhenAccessTokenAndIdTokenIsNull() {
        final var authService = new OidcAuthenticationService(defaultConfig(), oidcConfigurationMock, null, null);

        assertThat(authService.isSpecified()).isFalse();
    }

    @Test
    public void isSpecifiedShouldReturnFalseWhenOidcConfigurationIsNull() {
        final var authService = new OidcAuthenticationService(defaultConfig(), null, ID_TOKEN, ACCESS_TOKEN);

        assertThat(authService.isSpecified()).isFalse();
    }

    @Test
    public void isSpecifiedShouldReturnTrueWhenOidcIsEnabledAndOidcConfigurationIsNotNullAndAccessTokenIsNotNull() {
        final var authService = new OidcAuthenticationService(defaultConfig(), oidcConfigurationMock, ID_TOKEN, ACCESS_TOKEN);

        assertThat(authService.isSpecified()).isTrue();
    }

    @Test
    public void authenticateShouldAuthenticateExistingUserWithIdToken() throws Exception {
        OidcUser existingUser;
        try (final var qm = new AlpineQueryManager()) {
            existingUser = new OidcUser();
            existingUser.setUsername("username");
            existingUser.setSubjectIdentifier("subject");
            existingUser = qm.persist(existingUser);
        }

        final var profile = new OidcProfile();
        profile.setSubject(existingUser.getSubjectIdentifier());
        profile.setUsername(existingUser.getUsername());
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(profile);

        final var authService = new OidcAuthenticationService(defaultConfig(), oidcConfigurationMock, idTokenAuthenticatorMock, null, ID_TOKEN, null);

        final var authenticatedUser = (OidcUser) authService.authenticate();
        assertThat(authenticatedUser.getId()).isEqualTo(existingUser.getId());
        assertThat(authenticatedUser.getUsername()).isEqualTo(existingUser.getUsername());
        assertThat(authenticatedUser.getTeams()).isNullOrEmpty();
        assertThat(authenticatedUser.getEmail()).isNull();
    }

    @Test
    public void authenticateShouldAuthenticateExistingUserWithUserInfo() throws Exception {
        OidcUser existingUser;
        try (final var qm = new AlpineQueryManager()) {
            existingUser = new OidcUser();
            existingUser.setUsername("username");
            existingUser.setSubjectIdentifier("subject");
            existingUser = qm.persist(existingUser);
        }

        final var profile = new OidcProfile();
        profile.setSubject(existingUser.getSubjectIdentifier());
        profile.setUsername(existingUser.getUsername());
        when(userInfoAuthenticatorMock.authenticate(eq(ACCESS_TOKEN), any(OidcProfileCreator.class))).thenReturn(profile);

        final var authService = new OidcAuthenticationService(defaultConfig(), oidcConfigurationMock, null, userInfoAuthenticatorMock, null, ACCESS_TOKEN);

        final var authenticatedUser = (OidcUser) authService.authenticate();
        assertThat(authenticatedUser.getId()).isEqualTo(existingUser.getId());
        assertThat(authenticatedUser.getUsername()).isEqualTo(existingUser.getUsername());
        assertThat(authenticatedUser.getTeams()).isNullOrEmpty();
        assertThat(authenticatedUser.getEmail()).isNull();
    }

    @Test
    public void authenticateShouldThrowWhenUsernameClaimIsNotConfigured() {
        final Config config = configWith(Map.of(AlpineConfigKeys.OIDC_USERNAME_CLAIM, ""));

        final var authService = new OidcAuthenticationService(config, oidcConfigurationMock, ID_TOKEN, ACCESS_TOKEN);

        Assertions.assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticateShouldThrowWhenTeamSyncIsEnabledAndTeamsClaimIsNotConfigured() {
        final Config config = configWith(Map.of(AlpineConfigKeys.OIDC_TEAM_SYNCHRONIZATION, "true"));

        final var authService = new OidcAuthenticationService(config, oidcConfigurationMock, ID_TOKEN, ACCESS_TOKEN);

        Assertions.assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(authService::authenticate);
    }

    @Test
    public void authenticateShouldSynchronizeTeamsWhenUserAlreadyExistsAndTeamSynchronizationIsEnabled() throws Exception {
        final Config config = configWith(Map.of(
                AlpineConfigKeys.OIDC_TEAM_SYNCHRONIZATION, "true",
                AlpineConfigKeys.OIDC_TEAMS_CLAIM, "groups"));

        OidcUser existingUser;
        try (final var qm = new AlpineQueryManager()) {
            existingUser = new OidcUser();
            existingUser.setUsername("username");
            existingUser.setSubjectIdentifier("subject");
            qm.persist(existingUser);

            var group = new OidcGroup();
            group.setName("groupName");
            group = qm.persist(group);

            var teamToSync = new Team();
            teamToSync.setName("teamName");
            teamToSync = qm.persist(teamToSync);

            var mappedGroup = new MappedOidcGroup();
            mappedGroup.setGroup(group);
            mappedGroup.setTeam(teamToSync);
            qm.persist(mappedGroup);
        }

        final var profile = new OidcProfile();
        profile.setSubject("subject");
        profile.setUsername("username");
        profile.setGroups(List.of("groupName"));
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(profile);

        final var authService = new OidcAuthenticationService(config, oidcConfigurationMock, idTokenAuthenticatorMock, null, ID_TOKEN, null);

        final var authenticatedUser = (OidcUser) authService.authenticate();
        assertThat(authenticatedUser.getId()).isEqualTo(existingUser.getId());
        assertThat(authenticatedUser.getTeams()).hasSize(1);
        assertThat(authenticatedUser.getTeams().get(0).getName()).isEqualTo("teamName");
    }

    @Test
    public void authenticateShouldSourceProfileFromIdTokenAndUserInfoIfAvailable() throws Exception {
        final Config config = configWith(Map.of(
                AlpineConfigKeys.OIDC_USER_PROVISIONING, "true",
                AlpineConfigKeys.OIDC_TEAM_SYNCHRONIZATION, "true",
                AlpineConfigKeys.OIDC_TEAMS_CLAIM, "groups"));

        try (final var qm = new AlpineQueryManager()) {
            var group = new OidcGroup();
            group.setName("groupName");
            group = qm.persist(group);

            var teamToSync = new Team();
            teamToSync.setName("teamName");
            teamToSync = qm.persist(teamToSync);

            final var mappedGroup = new MappedOidcGroup();
            mappedGroup.setGroup(group);
            mappedGroup.setTeam(teamToSync);
            qm.persist(mappedGroup);
        }

        final var idTokenProfile = new OidcProfile();
        idTokenProfile.setSubject("subject");
        idTokenProfile.setUsername("username");
        idTokenProfile.setEmail("username@example.com");
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(idTokenProfile);

        final var userInfoProfile = new OidcProfile();
        userInfoProfile.setSubject("subject");
        userInfoProfile.setGroups(List.of("groupName"));
        when(userInfoAuthenticatorMock.authenticate(eq(ACCESS_TOKEN), any(OidcProfileCreator.class))).thenReturn(userInfoProfile);

        final var authService = new OidcAuthenticationService(config, oidcConfigurationMock, idTokenAuthenticatorMock, userInfoAuthenticatorMock, ID_TOKEN, ACCESS_TOKEN);

        final var provisionedUser = (OidcUser) authService.authenticate();
        assertThat(provisionedUser.getUsername()).isEqualTo("username");
        assertThat(provisionedUser.getSubjectIdentifier()).isEqualTo("subject");
        assertThat(provisionedUser.getTeams()).hasSize(1);
        assertThat(provisionedUser.getTeams().get(0).getName()).isEqualTo("teamName");
        assertThat(provisionedUser.getEmail()).isEqualTo("username@example.com");
    }

    @Test
    public void authenticateShouldThrowWhenUnableToAssembleCompleteProfile() throws Exception {
        final Config config = configWith(Map.of(
                AlpineConfigKeys.OIDC_USER_PROVISIONING, "true",
                AlpineConfigKeys.OIDC_TEAM_SYNCHRONIZATION, "true",
                AlpineConfigKeys.OIDC_TEAMS_CLAIM, "groups"));

        final var idTokenProfile = new OidcProfile();
        idTokenProfile.setSubject("subject");
        idTokenProfile.setUsername("username");
        idTokenProfile.setEmail("username@example.com");
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(idTokenProfile);

        final var userInfoProfile = new OidcProfile();
        userInfoProfile.setSubject("subject");
        userInfoProfile.setUsername("username");
        when(userInfoAuthenticatorMock.authenticate(eq(ACCESS_TOKEN), any(OidcProfileCreator.class))).thenReturn(userInfoProfile);

        final var authService = new OidcAuthenticationService(config, oidcConfigurationMock, idTokenAuthenticatorMock, userInfoAuthenticatorMock, ID_TOKEN, ACCESS_TOKEN);

        Assertions.assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(authService::authenticate)
                .satisfies(exception -> assertThat(exception.getCauseType())
                        .isEqualTo(AlpineAuthenticationException.CauseType.OTHER));
    }

    @Test
    public void authenticateShouldThrowWhenUserDoesNotExistAndProvisioningIsDisabled() throws Exception {
        final var profile = new OidcProfile();
        profile.setSubject("subject");
        profile.setUsername("username");
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(profile);

        final var authService = new OidcAuthenticationService(defaultConfig(), oidcConfigurationMock, idTokenAuthenticatorMock, null, ID_TOKEN, null);

        Assertions.assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(authService::authenticate)
                .satisfies(exception -> assertThat(exception.getCauseType())
                        .isEqualTo(AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT));
    }

    @Test
    public void authenticateShouldProvisionAndReturnNewUserWhenUserDoesNotExistAndProvisioningIsEnabled() throws Exception {
        final Config config = configWith(Map.of(AlpineConfigKeys.OIDC_USER_PROVISIONING, "true"));

        final var profile = new OidcProfile();
        profile.setSubject("subject");
        profile.setUsername("username");
        profile.setEmail("username@example.com");
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(profile);

        final var authService = new OidcAuthenticationService(config, oidcConfigurationMock, idTokenAuthenticatorMock, null, ID_TOKEN, null);

        final var provisionedUser = (OidcUser) authService.authenticate();
        assertThat(provisionedUser).isNotNull();
        assertThat(provisionedUser.getUsername()).isEqualTo("username");
        assertThat(provisionedUser.getSubjectIdentifier()).isEqualTo("subject");
        assertThat(provisionedUser.getEmail()).isEqualTo("username@example.com");
        assertThat(provisionedUser.getTeams()).isNullOrEmpty();
        assertThat(provisionedUser.getPermissions()).isNullOrEmpty();
    }

    @Test
    public void authenticateShouldProvisionAndApplyDefaultTeamsAndReturnNewUserWhenUserDoesNotExistAndProvisioningIsEnabled() throws Exception {
        final Config config = configWith(Map.of(
                AlpineConfigKeys.OIDC_USER_PROVISIONING, "true",
                AlpineConfigKeys.OIDC_DEFAULT_TEAMS, "teamName"));

        try (final var qm = new AlpineQueryManager()) {
            var teamToAssign = new Team();
            teamToAssign.setName("teamName");
            qm.persist(teamToAssign);
        }

        final var profile = new OidcProfile();
        profile.setSubject("subject");
        profile.setUsername("username");
        profile.setEmail("username@example.com");
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(profile);

        final var authService = new OidcAuthenticationService(config, oidcConfigurationMock, idTokenAuthenticatorMock, null, ID_TOKEN, null);

        final var provisionedUser = (OidcUser) authService.authenticate();
        assertThat(provisionedUser).isNotNull();
        assertThat(provisionedUser.getUsername()).isEqualTo("username");
        assertThat(provisionedUser.getSubjectIdentifier()).isEqualTo("subject");
        assertThat(provisionedUser.getEmail()).isEqualTo("username@example.com");
        assertThat(provisionedUser.getTeams()).hasSize(1);
        assertThat(provisionedUser.getTeams().get(0).getName()).isEqualTo("teamName");
        assertThat(provisionedUser.getPermissions()).isNullOrEmpty();
    }

    @Test
    public void authenticateShouldProvisionAndSyncTeamsAndReturnNewUserWhenUserDoesNotExistAndProvisioningAndTeamSyncIsEnabled() throws Exception {
        final Config config = configWith(Map.of(
                AlpineConfigKeys.OIDC_USER_PROVISIONING, "true",
                AlpineConfigKeys.OIDC_TEAM_SYNCHRONIZATION, "true",
                AlpineConfigKeys.OIDC_TEAMS_CLAIM, "groups"));

        try (final var qm = new AlpineQueryManager()) {
            var group = new OidcGroup();
            group.setName("groupName");
            group = qm.persist(group);

            var teamToSync = new Team();
            teamToSync.setName("teamName");
            teamToSync = qm.persist(teamToSync);

            var mappedGroup = new MappedOidcGroup();
            mappedGroup.setGroup(group);
            mappedGroup.setTeam(teamToSync);
            qm.persist(mappedGroup);
        }

        final var profile = new OidcProfile();
        profile.setSubject("subject");
        profile.setUsername("username");
        profile.setGroups(List.of("groupName"));
        profile.setEmail("username@example.com");
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(profile);

        final var authService = new OidcAuthenticationService(config, oidcConfigurationMock, idTokenAuthenticatorMock, null, ID_TOKEN, null);

        final var provisionedUser = (OidcUser) authService.authenticate();
        assertThat(provisionedUser).isNotNull();
        assertThat(provisionedUser.getUsername()).isEqualTo("username");
        assertThat(provisionedUser.getSubjectIdentifier()).isEqualTo("subject");
        assertThat(provisionedUser.getEmail()).isEqualTo("username@example.com");
        assertThat(provisionedUser.getTeams()).hasSize(1);
        assertThat(provisionedUser.getTeams().get(0).getName()).isEqualTo("teamName");
        assertThat(provisionedUser.getPermissions()).isNullOrEmpty();
    }

    @Test
    public void authenticateShouldAssignSubjectIdAndEmailWhenUserAlreadyExistsAndAuthenticatesForFirstTime() throws Exception {
        try (final AlpineQueryManager qm = new AlpineQueryManager()) {
            qm.createOidcUser("username");
        }

        final var profile = new OidcProfile();
        profile.setSubject("subject");
        profile.setUsername("username");
        profile.setEmail("username@example.com");
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(profile);

        final var authService = new OidcAuthenticationService(defaultConfig(), oidcConfigurationMock, idTokenAuthenticatorMock, null, ID_TOKEN, null);

        final var provisionedUser = (OidcUser) authService.authenticate();
        assertThat(provisionedUser).isNotNull();
        assertThat(provisionedUser.getUsername()).isEqualTo("username");
        assertThat(provisionedUser.getSubjectIdentifier()).isEqualTo("subject");
        assertThat(provisionedUser.getEmail()).isEqualTo("username@example.com");
        assertThat(provisionedUser.getTeams()).isNullOrEmpty();
        assertThat(provisionedUser.getPermissions()).isNullOrEmpty();
    }

    @Test
    public void authenticateShouldUpdateEmailWhenChangedSinceLastAuthentication() throws Exception {
        try (final var qm = new AlpineQueryManager()) {
            final OidcUser user = qm.createOidcUser("username");
            user.setSubjectIdentifier("subject");
            user.setEmail("username@example.com");
            qm.updateOidcUser(user);
        }

        final var profile = new OidcProfile();
        profile.setSubject("subject");
        profile.setUsername("username");
        profile.setEmail("username666@example.com");
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(profile);

        final var authService = new OidcAuthenticationService(defaultConfig(), oidcConfigurationMock, idTokenAuthenticatorMock, null, ID_TOKEN, null);

        final var provisionedUser = (OidcUser) authService.authenticate();
        assertThat(provisionedUser).isNotNull();
        assertThat(provisionedUser.getUsername()).isEqualTo("username");
        assertThat(provisionedUser.getSubjectIdentifier()).isEqualTo("subject");
        assertThat(provisionedUser.getEmail()).isEqualTo("username666@example.com");
        assertThat(provisionedUser.getTeams()).isNullOrEmpty();
        assertThat(provisionedUser.getPermissions()).isNullOrEmpty();

        try (final var qm = new AlpineQueryManager()) {
            final OidcUser user = qm.getOidcUser("username");
            assertThat(user.getEmail()).isEqualTo("username666@example.com");
        }
    }

    @Test
    public void authenticateShouldThrowWhenUserAlreadyExistsAndSubjectIdentifierHasChanged() throws Exception {
        try (final var qm = new AlpineQueryManager()) {
            final var existingUser = new OidcUser();
            existingUser.setUsername("username");
            existingUser.setSubjectIdentifier("subject");
            existingUser.setEmail("username@example.com");
            qm.persist(existingUser);
        }

        final var profile = new OidcProfile();
        profile.setSubject("changedSubject");
        profile.setUsername("username");
        profile.setEmail("username@example.com");
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(profile);

        final var authService = new OidcAuthenticationService(defaultConfig(), oidcConfigurationMock, idTokenAuthenticatorMock, null, ID_TOKEN, null);

        Assertions.assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(authService::authenticate)
                .satisfies(exception -> assertThat(exception.getCauseType())
                        .isEqualTo(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS));
    }

    @Test
    public void synchronizeTeamsShouldRemoveOutdatedTeamMemberships() throws Exception {
        final Config config = configWith(Map.of(
                AlpineConfigKeys.OIDC_TEAM_SYNCHRONIZATION, "true",
                AlpineConfigKeys.OIDC_TEAMS_CLAIM, "groups"));

        try (final var qm = new AlpineQueryManager()) {
            var oidcUser = new OidcUser();
            oidcUser.setUsername("username");
            oidcUser.setSubjectIdentifier("subject");
            oidcUser = qm.persist(oidcUser);

            var group = new OidcGroup();
            group.setName("groupName");
            group = qm.persist(group);

            var team = new Team();
            team.setName("teamName");
            team.setOidcUsers(List.of(oidcUser));
            team = qm.persist(team);

            final var mappedGroup = new MappedOidcGroup();
            mappedGroup.setGroup(group);
            mappedGroup.setTeam(team);
            qm.persist(mappedGroup);
        }

        final var profile = new OidcProfile();
        profile.setSubject("subject");
        profile.setUsername("username");
        profile.setGroups(Collections.emptyList());
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(profile);

        final var authService = new OidcAuthenticationService(config, oidcConfigurationMock, idTokenAuthenticatorMock, null, ID_TOKEN, null);

        final var authenticatedUser = (OidcUser) authService.authenticate();
        assertThat(authenticatedUser.getTeams()).isNullOrEmpty();
    }

    @Test
    public void authenticateShouldRemoveMembershipsOfUnmappedTeams() throws Exception {
        final Config config = configWith(Map.of(
                AlpineConfigKeys.OIDC_TEAM_SYNCHRONIZATION, "true",
                AlpineConfigKeys.OIDC_TEAMS_CLAIM, "groups"));

        try (final var qm = new AlpineQueryManager()) {
            var oidcUser = new OidcUser();
            oidcUser.setUsername("username");
            oidcUser.setSubjectIdentifier("subject");
            oidcUser = qm.persist(oidcUser);

            var team = new Team();
            team.setName("teamName");
            team.setOidcUsers(Collections.singletonList(oidcUser));
            qm.persist(team);
        }

        final var profile = new OidcProfile();
        profile.setSubject("subject");
        profile.setUsername("username");
        profile.setGroups(List.of("groupName"));
        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class))).thenReturn(profile);

        final var authService = new OidcAuthenticationService(config, oidcConfigurationMock, idTokenAuthenticatorMock, null, ID_TOKEN, null);

        final var authenticatedUser = (OidcUser) authService.authenticate();
        assertThat(authenticatedUser.getTeams()).isNullOrEmpty();
    }

    @Test
    public void authenticateShouldFallThroughToUserInfoWhenIdTokenLacksGroupsClaimAndTeamSyncIsEnabled() throws Exception {
        final Config config = configWith(Map.of(
                AlpineConfigKeys.OIDC_USER_PROVISIONING, "true",
                AlpineConfigKeys.OIDC_TEAM_SYNCHRONIZATION, "true",
                AlpineConfigKeys.OIDC_TEAMS_CLAIM, "groups"));

        try (final var qm = new AlpineQueryManager()) {
            var group = new OidcGroup();
            group.setName("groupName");
            group = qm.persist(group);

            var teamToSync = new Team();
            teamToSync.setName("teamName");
            teamToSync = qm.persist(teamToSync);

            final var mappedGroup = new MappedOidcGroup();
            mappedGroup.setGroup(group);
            mappedGroup.setTeam(teamToSync);
            qm.persist(mappedGroup);
        }

        final var customizer = new DefaultOidcAuthenticationCustomizer(USERNAME_CLAIM_NAME, "groups");
        final OidcProfile idTokenProfile = customizer.createProfile(
                new ClaimsSet(new JSONObject(Map.ofEntries(
                        Map.entry("sub", "subject"),
                        Map.entry(USERNAME_CLAIM_NAME, "username"),
                        Map.entry("email", "username@example.com")))));
        final OidcProfile userInfoProfile = customizer.createProfile(
                new ClaimsSet(new JSONObject(Map.ofEntries(
                        Map.entry("sub", "subject"),
                        Map.entry(USERNAME_CLAIM_NAME, "username"),
                        Map.entry("groups", List.of("groupName"))))));
        assertThat(idTokenProfile.getGroups()).isNull();

        when(idTokenAuthenticatorMock.authenticate(eq(ID_TOKEN), any(OidcProfileCreator.class)))
                .thenReturn(idTokenProfile);
        when(userInfoAuthenticatorMock.authenticate(eq(ACCESS_TOKEN), any(OidcProfileCreator.class)))
                .thenReturn(userInfoProfile);

        final var authService = new OidcAuthenticationService(
                config, oidcConfigurationMock, idTokenAuthenticatorMock, userInfoAuthenticatorMock, ID_TOKEN, ACCESS_TOKEN);

        final var authenticatedUser = (OidcUser) authService.authenticate();

        Mockito.verify(userInfoAuthenticatorMock).authenticate(eq(ACCESS_TOKEN), any(OidcProfileCreator.class));
        assertThat(authenticatedUser).isNotNull();
        assertThat(authenticatedUser.getUsername()).isEqualTo("username");
        assertThat(authenticatedUser.getSubjectIdentifier()).isEqualTo("subject");
        assertThat(authenticatedUser.getTeams()).hasSize(1);
        assertThat(authenticatedUser.getTeams().getFirst().getName()).isEqualTo("teamName");
    }

}
