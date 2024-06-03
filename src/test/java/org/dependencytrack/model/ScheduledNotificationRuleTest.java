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

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.Assert;
import org.junit.Test;

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Team;
import alpine.notification.NotificationLevel;

public class ScheduledNotificationRuleTest {
    @Test
    public void testId() {
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setId(111L);
        Assert.assertEquals(111L, rule.getId());
    }

    @Test
    public void testName() {
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setName("Test Name");
        Assert.assertEquals("Test Name", rule.getName());
    }

    @Test
    public void testEnabled() {
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setEnabled(true);
        Assert.assertTrue(rule.isEnabled());
    }

    @Test
    public void testScope() {
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setScope(NotificationScope.PORTFOLIO);
        Assert.assertEquals(NotificationScope.PORTFOLIO, rule.getScope());
    }

    @Test
    public void testNotificationLevel() {
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        Assert.assertEquals(NotificationLevel.INFORMATIONAL, rule.getNotificationLevel());
    }

    @Test
    public void testProjects() {
        List<Project> projects = new ArrayList<>();
        Project project = new Project();
        projects.add(project);
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setProjects(projects);
        Assert.assertEquals(1, rule.getProjects().size());
        Assert.assertEquals(project, rule.getProjects().get(0));
    }

    @Test
    public void testMessage() {
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setMessage("Test Message");
        Assert.assertEquals("Test Message", rule.getMessage());
    }

    @Test
    public void testNotifyOn() {
        Set<NotificationGroup> groups = new HashSet<>();
        groups.add(NotificationGroup.POLICY_VIOLATION);
        groups.add(NotificationGroup.NEW_VULNERABILITY);
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setNotifyOn(groups);
        Assert.assertEquals(2, rule.getNotifyOn().size());
    }

    @Test
    public void testPublisher() {
        NotificationPublisher publisher = new NotificationPublisher();
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setPublisher(publisher);
        Assert.assertEquals(publisher, rule.getPublisher());
    }

    @Test
    public void testPublisherConfig() {
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setPublisherConfig("{ \"config\": \"configured\" }");
        Assert.assertEquals("{ \"config\": \"configured\" }", rule.getPublisherConfig());
    }

    @Test
    public void testUuid() {
        UUID uuid = UUID.randomUUID();
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setUuid(uuid);
        Assert.assertEquals(uuid.toString(), rule.getUuid().toString());
    }

    @Test
    public void testTeams(){
        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        teams.add(team);
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setTeams(teams);
        Assert.assertEquals(1, rule.getTeams().size());
        Assert.assertEquals(team, rule.getTeams().get(0));
    }

    @Test
    public void testManagedUsers(){
        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        List<ManagedUser> managedUsers = new ArrayList<>();
        ManagedUser managedUser = new ManagedUser();
        managedUsers.add(managedUser);
        team.setManagedUsers(managedUsers);
        teams.add(team);
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setTeams(teams);
        Assert.assertEquals(1, rule.getTeams().size());
        Assert.assertEquals(team, rule.getTeams().get(0));
        Assert.assertEquals(managedUser, rule.getTeams().get(0).getManagedUsers().get(0));
    }

    @Test
    public void testLdapUsers(){
        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        List<LdapUser> ldapUsers = new ArrayList<>();
        LdapUser ldapUser = new LdapUser();
        ldapUsers.add(ldapUser);
        team.setLdapUsers(ldapUsers);
        teams.add(team);
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setTeams(teams);
        Assert.assertEquals(1, rule.getTeams().size());
        Assert.assertEquals(team, rule.getTeams().get(0));
        Assert.assertEquals(ldapUser, rule.getTeams().get(0).getLdapUsers().get(0));
    }

    @Test
    public void testOidcUsers(){
        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        List<OidcUser> oidcUsers = new ArrayList<>();
        OidcUser oidcUser = new OidcUser();
        oidcUsers.add(oidcUser);
        team.setOidcUsers(oidcUsers);
        teams.add(team);
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setTeams(teams);
        Assert.assertEquals(1, rule.getTeams().size());
        Assert.assertEquals(team, rule.getTeams().get(0));
        Assert.assertEquals(oidcUser, rule.getTeams().get(0).getOidcUsers().get(0));
    }

    @Test
    public void testCronExpression() {
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setCronConfig("0 0 12 * *");
        Assert.assertEquals("0 0 12 * *", rule.getCronConfig());
    }

    @Test
    public void testLastExecutionTime() {
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        ZonedDateTime zdt = ZonedDateTime.of(2024, 5, 20, 12, 10, 13, 0, ZoneOffset.UTC);
        rule.setLastExecutionTime(zdt);
        Assert.assertEquals(zdt, rule.getLastExecutionTime());
    }

    @Test
    public void testPublishOnlyWithUpdates() {
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setPublishOnlyWithUpdates(true);
        Assert.assertTrue(rule.getPublishOnlyWithUpdates());
    }
}
