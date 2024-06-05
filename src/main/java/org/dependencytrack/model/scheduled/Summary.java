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
package org.dependencytrack.model.scheduled;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;

public final class Summary {
    private final Map<Project, SummaryInfo> affectedProjectSummaries = new TreeMap<>();

    public Summary(final List<Project> affectedProjects, ZonedDateTime lastExecution) {
        try (var qm = new QueryManager()) {
            for (Project project : affectedProjects) {
                var findings = qm.getFindingsSince(project, false, lastExecution.withZoneSameInstant(ZoneOffset.UTC));
                affectedProjectSummaries.put(project, new SummaryInfo(findings));
            }
        }
    }

    public Map<Project, SummaryInfo> getAffectedProjectSummaries() {
        return affectedProjectSummaries;
    }
}
