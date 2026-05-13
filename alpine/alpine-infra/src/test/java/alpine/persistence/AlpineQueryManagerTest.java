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
package alpine.persistence;

import alpine.model.ApiKey;
import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.model.Team;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.jdo.JDOHelper;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AlpineQueryManagerTest {

    private JDOPersistenceManagerFactory pmf;
    private AlpineQueryManager qm;

    @BeforeEach
    void beforeEach() {
        pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(JdoProperties.unit(), "Alpine");
        qm = new AlpineQueryManager(pmf.getPersistenceManager());
    }

    @AfterEach
    void afterEach() {
        if (qm != null) {
            qm.close();
        }
        if (pmf != null) {
            pmf.close();
        }
    }

    @Test
    void shouldReturnTrueWhenUserHasDirectPermission() {
        final ManagedUser user = qm.callInTransaction(() -> {
            final Permission permission = qm.createPermission("FOO", null);
            final ManagedUser createdUser = qm.createManagedUser("alice", "hash");
            createdUser.setPermissions(List.of(permission));
            return createdUser;
        });

        assertThat(qm.hasPermission(user, "FOO", false)).isTrue();
        assertThat(qm.hasPermission(user, "FOO", true)).isTrue();
    }

    @Test
    void shouldReturnTrueWhenTeamGrantsPermissionAndIncludeTeams() {
        final ManagedUser user = qm.callInTransaction(() -> {
            final Permission permission = qm.createPermission("FOO", null);
            final Team team = qm.createTeam("team-a");
            team.setPermissions(List.of(permission));
            final ManagedUser createdUser = qm.createManagedUser("alice", "hash");
            qm.addUserToTeam(createdUser, team);
            return createdUser;
        });

        assertThat(qm.hasPermission(user, "FOO", true)).isTrue();
    }

    @Test
    void shouldReturnFalseWhenTeamGrantsPermissionButIncludeTeamsIsFalse() {
        final ManagedUser user = qm.callInTransaction(() -> {
            final Permission permission = qm.createPermission("FOO", null);
            final Team team = qm.createTeam("team-a");
            team.setPermissions(List.of(permission));
            final ManagedUser createdUser = qm.createManagedUser("alice", "hash");
            qm.addUserToTeam(createdUser, team);
            return createdUser;
        });

        assertThat(qm.hasPermission(user, "FOO", false)).isFalse();
    }

    @Test
    void shouldReturnTrueForTeamPermissionWhenUserIsDetached() {
        qm.callInTransaction(() -> {
            final Permission permission = qm.createPermission("FOO", null);
            final Team team = qm.createTeam("team-a");
            team.setPermissions(List.of(permission));
            final ManagedUser createdUser = qm.createManagedUser("alice", "hash");
            qm.addUserToTeam(createdUser, team);
            return createdUser;
        });

        final ManagedUser detached = qm.getManagedUser("alice");
        final long userId = detached.getId();
        qm.close();

        qm = new AlpineQueryManager(pmf.getPersistenceManager());
        final var stub = new ManagedUser();
        stub.setId(userId);

        assertThat(qm.hasPermission(stub, "FOO", true)).isTrue();
    }

    @Test
    void shouldReturnTrueWhenApiKeyTeamGrantsPermission() {
        final ApiKey apiKey = qm.callInTransaction(() -> {
            final Permission permission = qm.createPermission("FOO", null);
            final Team team = qm.createTeam("team-a");
            team.setPermissions(List.of(permission));
            return qm.createApiKey(team);
        });

        assertThat(qm.hasPermission(apiKey, "FOO")).isTrue();
        assertThat(qm.hasPermission(apiKey, "MISSING")).isFalse();
    }

    @Test
    void shouldReturnFalseWhenApiKeyHasNoTeams() {
        final ApiKey apiKey = qm.callInTransaction(() -> {
            final Team team = qm.createTeam("team-a");
            return qm.createApiKey(team);
        });

        assertThat(qm.hasPermission(apiKey, "FOO")).isFalse();
    }

    @Test
    void shouldReturnFalseWhenPermissionDoesNotExist() {
        final ManagedUser user = qm.callInTransaction(
                () -> qm.createManagedUser("alice", "hash"));

        assertThat(qm.hasPermission(user, "MISSING", true)).isFalse();
    }

}
