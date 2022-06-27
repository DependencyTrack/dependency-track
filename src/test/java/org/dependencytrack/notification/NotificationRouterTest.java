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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.notification;

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("unchecked")
public class NotificationRouterTest extends PersistenceCapableTest {

    @Test
    public void testNullNotification() {
        Notification notification = null;
        NotificationRouter router = new NotificationRouter();
        List<NotificationRule> rules = router.resolveRules(notification);
        Assert.assertEquals(0, rules.size());
    }

    @Test
    public void testInvalidNotification() {
        Notification notification = new Notification();
        NotificationRouter router = new NotificationRouter();
        List<NotificationRule> rules = router.resolveRules(notification);
        Assert.assertEquals(0, rules.size());
    }

    @Test
    public void testNoRules() {
        Notification notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.INFORMATIONAL);
        NotificationRouter router = new NotificationRouter();
        List<NotificationRule> rules = router.resolveRules(notification);
        Assert.assertEquals(0, rules.size());
    }

    @Test
    public void testValidMatchingRule() {
        NotificationPublisher publisher = createSlackPublisher();
        // Creates a new rule and defines when the rule should be triggered (notifyOn)
        NotificationRule rule = qm.createNotificationRule("Test Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Set<NotificationGroup> notifyOn = new HashSet<>();
        notifyOn.add(NotificationGroup.NEW_VULNERABILITY);
        rule.setNotifyOn(notifyOn);
        // Creates a new notification
        Notification notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.INFORMATIONAL);
        // Notification should not be limited to any projects - so set projects to null
        NewVulnerabilityIdentified subject = new NewVulnerabilityIdentified(new Vulnerability(), new Component(), null);
        notification.setSubject(subject);
        // Ok, let's test this
        NotificationRouter router = new NotificationRouter();
        List<NotificationRule> rules = router.resolveRules(notification);
        Assert.assertEquals(1, rules.size());
    }

    @Test
    public void testValidMatchingProjectLimitingRule() {
        NotificationPublisher publisher = createSlackPublisher();
        // Creates a new rule and defines when the rule should be triggered (notifyOn)
        NotificationRule rule = qm.createNotificationRule("Test Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Set<NotificationGroup> notifyOn = new HashSet<>();
        notifyOn.add(NotificationGroup.NEW_VULNERABILITY);
        rule.setNotifyOn(notifyOn);
        // Creates a project which will later be matched on
        List<Project> projects = new ArrayList<>();
        Project project = qm.createProject("Test Project", null, "1.0", null, null, null, true, false);
        projects.add(project);
        rule.setProjects(projects);
        // Creates a new notification
        Notification notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.INFORMATIONAL);
        // Notification should be limited to only specific projects - Set the projects which are affected by the notification event
        Set<Project> affectedProjects = new HashSet<>();
        affectedProjects.add(project);
        NewVulnerabilityIdentified subject = new NewVulnerabilityIdentified(new Vulnerability(), new Component(), affectedProjects);
        notification.setSubject(subject);
        // Ok, let's test this
        NotificationRouter router = new NotificationRouter();
        List<NotificationRule> rules = router.resolveRules(notification);
        Assert.assertEquals(1, rules.size());
    }

    @Test
    public void testValidNonMatchingProjectLimitingRule() {
        NotificationPublisher publisher = createSlackPublisher();
        // Creates a new rule and defines when the rule should be triggered (notifyOn)
        NotificationRule rule = qm.createNotificationRule("Test Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Set<NotificationGroup> notifyOn = new HashSet<>();
        notifyOn.add(NotificationGroup.NEW_VULNERABILITY);
        rule.setNotifyOn(notifyOn);
        // Creates a project which will later be matched on
        List<Project> projects = new ArrayList<>();
        Project project = qm.createProject("Test Project", null, "1.0", null, null, null, true, false);
        projects.add(project);
        rule.setProjects(projects);
        // Creates a new notification
        Notification notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.INFORMATIONAL);
        // Notification should be limited to only specific projects - Set the projects which are affected by the notification event
        Set<Project> affectedProjects = new HashSet<>();
        Project affectedProject = qm.createProject("Affected Project", null, "1.0", null, null, null, true, false);
        affectedProjects.add(affectedProject);
        NewVulnerabilityIdentified subject = new NewVulnerabilityIdentified(new Vulnerability(), new Component(), affectedProjects);
        notification.setSubject(subject);
        // Ok, let's test this
        NotificationRouter router = new NotificationRouter();
        List<NotificationRule> rules = router.resolveRules(notification);
        Assert.assertEquals(1, rules.size());
    }

    @Test
    public void testValidNonMatchingRule() {
        NotificationPublisher publisher = createSlackPublisher();
        // Creates a new rule and defines when the rule should be triggered (notifyOn)
        NotificationRule rule = qm.createNotificationRule("Test Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Set<NotificationGroup> notifyOn = new HashSet<>();
        notifyOn.add(NotificationGroup.PROJECT_AUDIT_CHANGE);
        rule.setNotifyOn(notifyOn);
        // Creates a new notification
        Notification notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.INFORMATIONAL);
        // Notification should not be limited to any projects - so set projects to null
        NewVulnerabilityIdentified subject = new NewVulnerabilityIdentified(new Vulnerability(), new Component(), null);
        notification.setSubject(subject);
        // Ok, let's test this
        NotificationRouter router = new NotificationRouter();
        List<NotificationRule> rules = router.resolveRules(notification);
        Assert.assertEquals(0, rules.size());
    }

    @Test
    public void testRuleLevelEqual() {
        final NotificationPublisher publisher = createSlackPublisher();
        final NotificationRule rule = qm.createNotificationRule("Test Rule", NotificationScope.PORTFOLIO, NotificationLevel.WARNING, publisher);
        rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITY));

        final var notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.WARNING); // Rule level is equal

        final var router = new NotificationRouter();
        assertThat(router.resolveRules(notification)).hasSize(1);
    }

    @Test
    public void testRuleLevelBelow() {
        final NotificationPublisher publisher = createSlackPublisher();
        final NotificationRule rule = qm.createNotificationRule("Test Rule", NotificationScope.PORTFOLIO, NotificationLevel.WARNING, publisher);
        rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITY));

        final var notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.ERROR); // Rule level is lower

        final var router = new NotificationRouter();
        assertThat(router.resolveRules(notification)).hasSize(1);
    }

    @Test
    public void testRuleLevelAbove() {
        final NotificationPublisher publisher = createSlackPublisher();

        final NotificationRule rule = qm.createNotificationRule("Test Rule", NotificationScope.PORTFOLIO, NotificationLevel.WARNING, publisher);
        rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITY));

        final var notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.INFORMATIONAL); // Rule level is higher

        final var router = new NotificationRouter();
        assertThat(router.resolveRules(notification)).isEmpty();
    }

    @Test
    public void testDisabledRule() {
        final NotificationPublisher publisher = createSlackPublisher();

        final NotificationRule rule = qm.createNotificationRule("Test Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITY));
        rule.setEnabled(false);

        final var notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.INFORMATIONAL);

        final var router = new NotificationRouter();
        assertThat(router.resolveRules(notification)).isEmpty();
    }

    private NotificationPublisher createSlackPublisher() {
        return qm.createNotificationPublisher(
                DefaultNotificationPublishers.SLACK.getPublisherName(),
                DefaultNotificationPublishers.SLACK.getPublisherDescription(),
                DefaultNotificationPublishers.SLACK.getPublisherClass(),
                null, DefaultNotificationPublishers.SLACK.getTemplateMimeType(),
                DefaultNotificationPublishers.SLACK.isDefaultPublisher()
        );
    }
}
