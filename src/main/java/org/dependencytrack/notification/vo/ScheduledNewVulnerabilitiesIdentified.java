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
package org.dependencytrack.notification.vo;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;

public class ScheduledNewVulnerabilitiesIdentified {
    private final Map<Project, List<Vulnerability>> newProjectVulnerabilities;
    private final Map<Project, Map<Severity, List<Vulnerability>>> newProjectVulnerabilitiesBySeverity;
    private final List<Vulnerability> newVulnerabilitiesTotal;
    private final Map<Severity, List<Vulnerability>> newVulnerabilitiesTotalBySeverity;

    public ScheduledNewVulnerabilitiesIdentified(Map<Project, List<Vulnerability>> newProjectVulnerabilities) {
        this.newProjectVulnerabilities = newProjectVulnerabilities;
        this.newProjectVulnerabilitiesBySeverity = newProjectVulnerabilities.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().stream()
                        .collect(Collectors.groupingBy(Vulnerability::getSeverity, () -> new EnumMap<>(Severity.class), Collectors.toList()))));
        this.newVulnerabilitiesTotal = newProjectVulnerabilities.values().stream()
                .flatMap(List::stream)
                .collect(Collectors.toList());
        this.newVulnerabilitiesTotalBySeverity = newVulnerabilitiesTotal.stream()
                .collect(Collectors.groupingBy(Vulnerability::getSeverity, () -> new EnumMap<>(Severity.class), Collectors.toList()));
    }

    public Map<Project, List<Vulnerability>> getNewProjectVulnerabilities() {
        return newProjectVulnerabilities;
    }

    public Map<Project, Map<Severity, List<Vulnerability>>> getNewProjectVulnerabilitiesBySeverity() {
        return newProjectVulnerabilitiesBySeverity;
    }

    public List<Vulnerability> getNewVulnerabilitiesTotal() {
        return newVulnerabilitiesTotal;
    }

    public Map<Severity, List<Vulnerability>> getNewVulnerabilitiesTotalBySeverity() {
        return newVulnerabilitiesTotalBySeverity;
    }
}
