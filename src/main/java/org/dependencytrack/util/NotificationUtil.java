/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.util;

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Dependency;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.persistence.QueryManager;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class NotificationUtil {

    public static void analyzeNotificationCriteria(Vulnerability vulnerability, Component component) {
        QueryManager qm = new QueryManager();
        if (!qm.contains(vulnerability, component)) {
            // Component did not previously contain this vulnerability. It could be a newly discovered vulnerability
            // against an existing component, or it could be a newly added (and vulnerable) component. Either way,
            // it warrants a Notification be dispatched.
            Set<Project> affectedProjects = new HashSet<>();
            List<Dependency> dependencies = qm.getAllDependencies(component);
            for (Dependency dependency : dependencies) {
                affectedProjects.add(dependency.getProject());
            }
            Notification.dispatch(new Notification()
                    .scope(NotificationConstants.Scope.PORTFOLIO)
                    .group(NotificationConstants.Group.NEW_VULNERABILITY)
                    .title(NotificationConstants.Title.NEW_VULNERABILITY)
                    .level(NotificationLevel.INFORMATIONAL)
                    .subject(new NewVulnerabilityIdentified(vulnerability, component, affectedProjects))
            );
        }
    }

    public static void analyzeNotificationCriteria(QueryManager qm, Dependency newDependency) {
        Dependency dependency = qm.getDependency(newDependency);
        List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(dependency);
        for (Vulnerability vulnerability: vulnerabilities) {
            Set<Project> affectedProjects = new HashSet<>(Collections.singletonList(dependency.getProject()));
            Notification.dispatch(new Notification()
                    .scope(NotificationConstants.Scope.PORTFOLIO)
                    .group(NotificationConstants.Group.NEW_VULNERABILITY)
                    .title(NotificationConstants.Title.NEW_VULNERABLE_DEPENDENCY)
                    .level(NotificationLevel.INFORMATIONAL)
                    .subject(new NewVulnerabilityIdentified(vulnerability, dependency.getComponent(), affectedProjects))
            );
        }
    }

    public static void analyzeNotificationCriteria(QueryManager qm, Analysis analysis, boolean hasChanged) {
        if (AnalysisState.EXPLOITABLE == analysis.getAnalysisState() && hasChanged) {
            final NotificationConstants.Group notificationGroup;
            final Set<Project> affectedProjects = new HashSet<>();
            if (analysis.getProject() != null) {
                // This was an analysis decision affecting a single project
                notificationGroup = NotificationConstants.Group.PROJECT_AUDIT_CHANGE;
                affectedProjects.add(analysis.getProject());
            } else {
                // This was a global analysis decision affecting all projects
                notificationGroup = NotificationConstants.Group.GLOBAL_AUDIT_CHANGE;
                List<Dependency> dependencies = qm.getAllDependencies(analysis.getProject());
                for (Dependency dependency : dependencies) {
                    affectedProjects.add(dependency.getProject());
                }
            }
            Notification.dispatch(new Notification()
                    .scope(NotificationConstants.Scope.PORTFOLIO)
                    .group(notificationGroup)
                    .title(NotificationConstants.Title.EXPLOITABLE_ANALYSIS_DECISION)
                    .level(NotificationLevel.INFORMATIONAL)
                    .subject(new NewVulnerabilityIdentified(analysis.getVulnerability(), analysis.getComponent(), affectedProjects))
            );
        }
    }

}
