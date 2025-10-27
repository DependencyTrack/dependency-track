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
package org.dependencytrack.model;

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Team;
import alpine.notification.NotificationLevel;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

class NotificationRuleTest {

    @Test
    void testId() {
        NotificationRule rule = new NotificationRule();
        rule.setId(111L);
        Assertions.assertEquals(111L, rule.getId());
    }

    @Test
    void testName() {
        NotificationRule rule = new NotificationRule();
        rule.setName("Test Name");
        Assertions.assertEquals("Test Name", rule.getName());
    }

    @Test
    void testEnabled() {
        NotificationRule rule = new NotificationRule();
        rule.setEnabled(true);
        Assertions.assertTrue(rule.isEnabled());
    }

    @Test
    void testScope() {
        NotificationRule rule = new NotificationRule();
        rule.setScope(NotificationScope.PORTFOLIO);
        Assertions.assertEquals(NotificationScope.PORTFOLIO, rule.getScope());
    }

    @Test
    void testNotificationLevel() {
        NotificationRule rule = new NotificationRule();
        rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        Assertions.assertEquals(NotificationLevel.INFORMATIONAL, rule.getNotificationLevel());
    }

    @Test
    void testProjects() {
        List<Project> projects = new ArrayList<>();
        Project project = new Project();
        projects.add(project);
        NotificationRule rule = new NotificationRule();
        rule.setProjects(projects);
        Assertions.assertEquals(1, rule.getProjects().size());
        Assertions.assertEquals(project, rule.getProjects().get(0));
    }

    @Test
    void testMessage() {
        NotificationRule rule = new NotificationRule();
        rule.setMessage("Test Message");
        Assertions.assertEquals("Test Message", rule.getMessage());
    }

    @Test
    void testNotifyOn() {
        Set<NotificationGroup> groups = new HashSet<>();
        groups.add(NotificationGroup.NEW_VULNERABLE_DEPENDENCY);
        groups.add(NotificationGroup.NEW_VULNERABILITY);
        NotificationRule rule = new NotificationRule();
        rule.setNotifyOn(groups);
        Assertions.assertEquals(2, rule.getNotifyOn().size());
    }

    @Test
    public void testNotifySeverities() {
        List<Severity> severities = new ArrayList<>();
        severities.add(Severity.LOW);
        severities.add(Severity.CRITICAL);
        NotificationRule rule = new NotificationRule();
        rule.setNotifySeverities(severities);
        Assertions.assertEquals(2, rule.getNotifySeverities().size());
    }

    @Test
    void testPublisher() {
        NotificationPublisher publisher = new NotificationPublisher();
        NotificationRule rule = new NotificationRule();
        rule.setPublisher(publisher);
        Assertions.assertEquals(publisher, rule.getPublisher());
    }

    @Test
    void testPublisherConfig() {
        NotificationRule rule = new NotificationRule();
        rule.setPublisherConfig("{ \"config\": \"configured\" }");
        Assertions.assertEquals("{ \"config\": \"configured\" }", rule.getPublisherConfig());
    }

    @Test
    void testUuid() {
        UUID uuid = UUID.randomUUID();
        NotificationRule rule = new NotificationRule();
        rule.setUuid(uuid);
        Assertions.assertEquals(uuid.toString(), rule.getUuid().toString());
    }

    @Test
    void testTeams(){
        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        teams.add(team);
        NotificationRule rule = new NotificationRule();
        rule.setTeams(teams);
        Assertions.assertEquals(1, rule.getTeams().size());
        Assertions.assertEquals(team, rule.getTeams().get(0));
    }

    @Test
    void testManagedUsers(){
        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        List<ManagedUser> managedUsers = new ArrayList<>();
        ManagedUser managedUser = new ManagedUser();
        managedUsers.add(managedUser);
        team.setManagedUsers(managedUsers);
        teams.add(team);
        NotificationRule rule = new NotificationRule();
        rule.setTeams(teams);
        Assertions.assertEquals(1, rule.getTeams().size());
        Assertions.assertEquals(team, rule.getTeams().get(0));
        Assertions.assertEquals(managedUser, rule.getTeams().get(0).getManagedUsers().get(0));
    }

    @Test
    void testLdapUsers(){
        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        List<LdapUser> ldapUsers = new ArrayList<>();
        LdapUser ldapUser = new LdapUser();
        ldapUsers.add(ldapUser);
        team.setLdapUsers(ldapUsers);
        teams.add(team);
        NotificationRule rule = new NotificationRule();
        rule.setTeams(teams);
        Assertions.assertEquals(1, rule.getTeams().size());
        Assertions.assertEquals(team, rule.getTeams().get(0));
        Assertions.assertEquals(ldapUser, rule.getTeams().get(0).getLdapUsers().get(0));
    }

    @Test
    void testOidcUsers(){
        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        List<OidcUser> oidcUsers = new ArrayList<>();
        OidcUser oidcUser = new OidcUser();
        oidcUsers.add(oidcUser);
        team.setOidcUsers(oidcUsers);
        teams.add(team);
        NotificationRule rule = new NotificationRule();
        rule.setTeams(teams);
        Assertions.assertEquals(1, rule.getTeams().size());
        Assertions.assertEquals(team, rule.getTeams().get(0));
        Assertions.assertEquals(oidcUser, rule.getTeams().get(0).getOidcUsers().get(0));
    }
}
