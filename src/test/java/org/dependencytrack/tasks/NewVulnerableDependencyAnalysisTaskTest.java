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
package org.dependencytrack.tasks;

import alpine.notification.Notification;
import alpine.notification.NotificationService;
import alpine.notification.Subscription;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.NewVulnerableDependencyAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.dependencytrack.util.NotificationUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;

class NewVulnerableDependencyAnalysisTaskTest extends PersistenceCapableTest {

    public static class NotificationSubscriber implements alpine.notification.Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    @BeforeEach
    public void setUp() {
        NotificationService.getInstance().subscribe(new Subscription(NotificationSubscriber.class));
    }

    @AfterEach
    public void tearDown() {
        NotificationService.getInstance().unsubscribe(new Subscription(NotificationSubscriber.class));
        NOTIFICATIONS.clear();
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/6556
    void shouldIncludeProjectTags() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);
        qm.bind(project, qm.createTags(List.of("foo", "bar")));

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        qm.persist(vuln);
        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER);

        new NewVulnerableDependencyAnalysisTask().inform(new NewVulnerableDependencyAnalysisEvent(List.of(component)));

        assertConditionWithTimeout(() -> !NOTIFICATIONS.isEmpty(), Duration.ofSeconds(5));
        assertThat(NOTIFICATIONS).satisfiesExactly(notification -> {
            assertThat(notification.getGroup()).isEqualTo(NotificationGroup.NEW_VULNERABLE_DEPENDENCY.name());
            final var subject = (NewVulnerableDependency) notification.getSubject();
            assertThat(NotificationUtil.toJson(subject).getJsonObject("project").getString("tags", null)).isEqualTo("bar,foo");
        });
    }

}
