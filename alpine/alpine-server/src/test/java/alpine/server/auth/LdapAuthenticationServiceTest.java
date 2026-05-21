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
package alpine.server.auth;

import alpine.config.AlpineConfigKeys;
import alpine.model.LdapUser;
import alpine.model.Team;
import alpine.persistence.AlpineQueryManager;
import alpine.server.persistence.PersistenceManagerFactory;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.ldap.LLdapContainer;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@Testcontainers
class LdapAuthenticationServiceTest {

    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_DN = "uid=admin,ou=people,dc=example,dc=com";
    private static final String ADMIN_PASSWORD = "password";

    @Container
    private static final LLdapContainer LDAP = new LLdapContainer("lldap/lldap:2026-03-04-alpine")
            .withUserPass(ADMIN_PASSWORD)
            .withEnv("LLDAP_JWT_SECRET", "0123456789abcdef0123456789abcdef");

    @AfterEach
    void tearDown() {
        PersistenceManagerFactory.tearDown();
    }

    @Test
    void shouldAuthenticateAndAutoProvisionUserWhenCredentialsAreValid() throws Exception {
        final var authService = new LdapAuthenticationService(defaultConfig(), ADMIN_USERNAME, ADMIN_PASSWORD);

        final var principal = (LdapUser) authService.authenticate();

        assertThat(principal).isNotNull();
        assertThat(principal.getUsername()).isEqualTo(ADMIN_USERNAME);
        assertThat(principal.getDN()).isEqualToIgnoringCase(ADMIN_DN);

        try (final var qm = new AlpineQueryManager()) {
            assertThat(qm.getLdapUser(ADMIN_USERNAME)).isNotNull();
        }
    }

    @Test
    void shouldReturnExistingLdapUserWhenAlreadyProvisioned() throws Exception {
        try (final var qm = new AlpineQueryManager()) {
            final var existing = new LdapUser();
            existing.setUsername(ADMIN_USERNAME);
            existing.setDN(ADMIN_DN);
            qm.persist(existing);
        }

        final var authService = new LdapAuthenticationService(defaultConfig(), ADMIN_USERNAME, ADMIN_PASSWORD);

        final var principal = (LdapUser) authService.authenticate();

        assertThat(principal).isNotNull();
        assertThat(principal.getUsername()).isEqualTo(ADMIN_USERNAME);
        assertThat(principal.getDN()).isEqualToIgnoringCase(ADMIN_DN);
    }

    @Test
    void shouldRefreshDnAndEmailWhenExistingUserLogsIn() throws Exception {
        // Pre-seed a user with a missing DN and a stale email.
        // Login must populate the DN from LDAP and overwrite the email with whatever
        // the directory reports, i.e. null for the lldap admin,
        // which has no mail attribute set out of the box.
        try (final var qm = new AlpineQueryManager()) {
            final var existing = new LdapUser();
            existing.setUsername(ADMIN_USERNAME);
            existing.setEmail("stale@example.com");
            qm.persist(existing);
        }

        final var authService = new LdapAuthenticationService(defaultConfig(), ADMIN_USERNAME, ADMIN_PASSWORD);

        final var principal = (LdapUser) authService.authenticate();
        assertThat(principal).isNotNull();
        assertThat(principal.getDN()).isEqualToIgnoringCase(ADMIN_DN);
        assertThat(principal.getEmail()).isNull();

        try (final var qm = new AlpineQueryManager()) {
            final LdapUser persisted = qm.getLdapUser(ADMIN_USERNAME);
            assertThat(persisted.getDN()).isEqualToIgnoringCase(ADMIN_DN);
            assertThat(persisted.getEmail()).isNull();
        }
    }

    @Test
    void shouldThrowInvalidCredentialsWhenPasswordIsWrong() {
        final var authService = new LdapAuthenticationService(defaultConfig(), ADMIN_USERNAME, "wrong-password");

        assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(authService::authenticate)
                .satisfies(e -> assertThat(e.getCauseType())
                        .isEqualTo(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS));
    }

    @Test
    void shouldThrowInvalidCredentialsWhenUserDoesNotExist() {
        final var authService = new LdapAuthenticationService(defaultConfig(), "does-not-exist", ADMIN_PASSWORD);

        assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(authService::authenticate)
                .satisfies(e -> assertThat(e.getCauseType())
                        .isEqualTo(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS));
    }

    @Test
    void shouldSyncTeamMembershipWhenAutoProvisioningWithTeamSyncEnabled() throws Exception {
        // NB: The lldap admin user is a member of the built-in lldap_admin group out of the box.
        final String adminGroupDn = "cn=lldap_admin,ou=groups,dc=example,dc=com";

        try (final var qm = new AlpineQueryManager()) {
            var team = new Team();
            team.setName("admins");
            team = qm.persist(team);
            qm.createMappedLdapGroup(team, adminGroupDn);
        }

        final Config config = configWith(Map.of(AlpineConfigKeys.LDAP_TEAM_SYNCHRONIZATION, "true"));
        final var authService = new LdapAuthenticationService(config, ADMIN_USERNAME, ADMIN_PASSWORD);

        final var principal = (LdapUser) authService.authenticate();

        assertThat(principal.getTeams()).extracting(Team::getName).containsExactly("admins");
    }

    @Test
    void shouldRefreshTeamMembershipWhenExistingUserLogsInWithTeamSyncEnabled() throws Exception {
        final String adminGroupDn = "cn=lldap_admin,ou=groups,dc=example,dc=com";
        final String absentGroupDn = "cn=other-group,ou=groups,dc=example,dc=com";

        try (final var qm = new AlpineQueryManager()) {
            // staleTeam is mapped to a group the admin user is NOT in.
            // synchronizeTeamMembership should remove the admin from it.
            var staleTeam = new Team();
            staleTeam.setName("stale-team");
            staleTeam = qm.persist(staleTeam);
            qm.createMappedLdapGroup(staleTeam, absentGroupDn);

            var adminTeam = new Team();
            adminTeam.setName("admins");
            adminTeam = qm.persist(adminTeam);
            qm.createMappedLdapGroup(adminTeam, adminGroupDn);

            final var existing = new LdapUser();
            existing.setUsername(ADMIN_USERNAME);
            existing.setDN(ADMIN_DN);
            qm.persist(existing);
            qm.addUserToTeam(existing, staleTeam);
        }

        final Config config = configWith(Map.of(AlpineConfigKeys.LDAP_TEAM_SYNCHRONIZATION, "true"));
        final var authService = new LdapAuthenticationService(config, ADMIN_USERNAME, ADMIN_PASSWORD);

        final var principal = (LdapUser) authService.authenticate();

        assertThat(principal.getTeams()).extracting(Team::getName).containsExactly("admins");
    }

    @Test
    void shouldThrowUnmappedAccountWhenProvisioningIsDisabled() {
        final Config config = configWith(Map.of(AlpineConfigKeys.LDAP_USER_PROVISIONING, "false"));

        final var authService = new LdapAuthenticationService(config, ADMIN_USERNAME, ADMIN_PASSWORD);

        assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(authService::authenticate)
                .satisfies(e -> assertThat(e.getCauseType())
                        .isEqualTo(AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT));
    }

    private static Config configWith(Map<String, String> overrides) {
        final var values = new HashMap<String, String>();
        values.put(AlpineConfigKeys.LDAP_ENABLED, "true");
        values.put(AlpineConfigKeys.LDAP_SERVER_URL, LDAP.getLdapUrl());
        values.put(AlpineConfigKeys.LDAP_BASEDN, LDAP.getBaseDn());
        values.put(AlpineConfigKeys.LDAP_BIND_USERNAME, LDAP.getUser());
        values.put(AlpineConfigKeys.LDAP_BIND_PASSWORD, LDAP.getPassword());
        values.put(AlpineConfigKeys.LDAP_ATTRIBUTE_NAME, "uid");
        values.put(AlpineConfigKeys.LDAP_ATTRIBUTE_MAIL, "mail");
        values.put(AlpineConfigKeys.LDAP_USER_GROUPS_FILTER, "(member={USER_DN})");
        values.put(AlpineConfigKeys.LDAP_GROUPS_FILTER, "(objectClass=groupOfUniqueNames)");
        values.put(AlpineConfigKeys.LDAP_GROUPS_SEARCH_FILTER, "(&(objectClass=groupOfUniqueNames)(cn=*{SEARCH_TERM}*))");
        values.put(AlpineConfigKeys.LDAP_USERS_SEARCH_FILTER, "(&(objectClass=inetOrgPerson)(cn=*{SEARCH_TERM}*))");
        values.put(AlpineConfigKeys.LDAP_USER_PROVISIONING, "true");
        values.put(AlpineConfigKeys.LDAP_TEAM_SYNCHRONIZATION, "false");
        values.putAll(overrides);
        return new SmallRyeConfigBuilder().withDefaultValues(values).build();
    }

    private static Config defaultConfig() {
        return configWith(Map.of());
    }

}
