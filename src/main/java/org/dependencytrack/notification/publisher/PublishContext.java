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
package org.dependencytrack.notification.publisher;

import alpine.notification.Notification;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.notification.vo.PolicyViolationIdentified;
import org.dependencytrack.notification.vo.VexConsumedOrProcessed;
import org.dependencytrack.notification.vo.ViolationAnalysisDecisionChange;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Context information about a {@link Notification} being published.
 *
 * @param notificationGroup     Group of the {@link Notification} being published
 * @param notificationLevel     Level of the {@link Notification} being published
 * @param notificationScope     Scope of the {@link Notification} being published
 * @param notificationTimestamp UTC Timestamp in {@link DateTimeFormatter#ISO_DATE_TIME} of the {@link Notification} being published
 * @param notificationSubjects  Subject(s) of the {@link Notification} being published
 * @param ruleName              Name of the matched {@link NotificationRule}
 * @param ruleScope             Scope of the matched {@link NotificationRule}
 * @param ruleLevel             Level of the matched {@link NotificationRule}
 * @since 4.10.0
 */
public record PublishContext(String notificationGroup, String notificationLevel, String notificationScope,
                             String notificationTimestamp, Map<String, Object> notificationSubjects,
                             String ruleName, String ruleScope, String ruleLevel) {

    private static final String SUBJECT_COMPONENT = "component";
    private static final String SUBJECT_PROJECT = "project";
    private static final String SUBJECT_PROJECTS = "projects";

    public static PublishContext from(final Notification notification) {
        final var notificationSubjects = new HashMap<String, Object>();
        if (notification.getSubject() instanceof final BomConsumedOrProcessed subject) {
            notificationSubjects.put(SUBJECT_PROJECT, Project.convert(subject.getProject()));
        } else if (notification.getSubject() instanceof final BomProcessingFailed subject) {
            notificationSubjects.put(SUBJECT_PROJECT, Project.convert(subject.getProject()));
        } else if (notification.getSubject() instanceof final NewVulnerabilityIdentified subject) {
            notificationSubjects.put(SUBJECT_COMPONENT, Component.convert(subject.getComponent()));
            if (subject.getAffectedProjects() != null) {
                notificationSubjects.put(SUBJECT_PROJECTS, subject.getAffectedProjects().stream().map(Project::convert).toList());
            } else {
                notificationSubjects.put(SUBJECT_PROJECTS, null);
            }
        } else if (notification.getSubject() instanceof final NewVulnerableDependency subject) {
            notificationSubjects.put(SUBJECT_COMPONENT, Component.convert(subject.getComponent()));
            notificationSubjects.put(SUBJECT_PROJECT, Project.convert(subject.getComponent().getProject()));
        } else if (notification.getSubject() instanceof final org.dependencytrack.model.Project subject) {
            notificationSubjects.put(SUBJECT_PROJECT, Project.convert(subject));
        } else if (notification.getSubject() instanceof final PolicyViolationIdentified subject) {
            notificationSubjects.put(SUBJECT_COMPONENT, Component.convert(subject.getComponent()));
            notificationSubjects.put(SUBJECT_PROJECT, Project.convert(subject.getProject()));
        } else if (notification.getSubject() instanceof final ViolationAnalysisDecisionChange subject) {
            notificationSubjects.put(SUBJECT_COMPONENT, Component.convert(subject.getComponent()));
            notificationSubjects.put(SUBJECT_PROJECT, Project.convert(subject.getComponent().getProject()));
        } else if (notification.getSubject() instanceof final AnalysisDecisionChange subject) {
            notificationSubjects.put(SUBJECT_COMPONENT, Component.convert(subject.getComponent()));
            notificationSubjects.put(SUBJECT_PROJECT, Project.convert(subject.getProject()));
        } else if (notification.getSubject() instanceof final VexConsumedOrProcessed subject) {
            notificationSubjects.put(SUBJECT_PROJECT, Project.convert(subject.getProject()));
        }

        return new PublishContext(notification.getGroup(), notification.getLevel().name(), notification.getScope(),
                notification.getTimestamp().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_DATE_TIME), notificationSubjects,
                /* ruleName */ null, /* ruleScope */ null, /* ruleLevel */ null);
    }

    /**
     * Enrich the {@link PublishContext} with additional information about the {@link NotificationRule} once known.
     *
     * @param rule The applicable {@link NotificationRule}
     * @return This {@link PublishContext}
     */
    public PublishContext withRule(final NotificationRule rule) {
        return new PublishContext(this.notificationGroup, this.notificationLevel, this.notificationScope, this.notificationTimestamp,
                this.notificationSubjects, rule.getName(), rule.getScope().name(), rule.getNotificationLevel().name());
    }

    public record Component(String uuid, String group, String name, String version) {

        private static Component convert(final org.dependencytrack.model.Component notificationComponent) {
            if (notificationComponent == null) {
                return null;
            }
            return new Component(
                    Optional.ofNullable(notificationComponent.getUuid()).map(UUID::toString).orElse(null),
                    notificationComponent.getGroup(),
                    notificationComponent.getName(),
                    notificationComponent.getVersion()
            );
        }

    }

    public record Project(String uuid, String name, String version) {

        private static Project convert(final org.dependencytrack.model.Project notificationProject) {
            if (notificationProject == null) {
                return null;
            }
            return new Project(
                    Optional.ofNullable(notificationProject.getUuid()).map(UUID::toString).orElse(null),
                    notificationProject.getName(),
                    notificationProject.getVersion()
            );
        }

    }

}
