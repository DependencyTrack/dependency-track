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
package org.owasp.dependencytrack.util;

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.Dependency;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.notification.NotificationConstants;
import org.owasp.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.owasp.dependencytrack.persistence.QueryManager;

import java.util.*;

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

}
