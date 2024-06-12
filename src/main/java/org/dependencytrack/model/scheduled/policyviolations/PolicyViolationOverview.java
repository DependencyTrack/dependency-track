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
package org.dependencytrack.model.scheduled.policyviolations;

import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;

public final class PolicyViolationOverview {
    private final Integer affectedProjectsCount;
    private final Integer newViolationsCount;
    private final Map<PolicyViolation.Type, Integer> newViolationsByRiskType = new EnumMap<>(PolicyViolation.Type.class);
    private final Integer affectedComponentsCount;
    private final Integer suppressedNewViolationsCount;

    public PolicyViolationOverview(Map<Project, List<PolicyViolation>> affectedProjectViolations) {
        var componentCache = new HashSet<Component>();
        var violationCache = new HashSet<PolicyViolation>();
        var suppressedViolationCache = new HashSet<PolicyViolation>();

        try (var qm = new QueryManager()) {
            for (var violations : affectedProjectViolations.values()) {
                for (PolicyViolation violation : violations) {
                    Component component = qm.getObjectByUuid(Component.class, violation.getComponent().getUuid().toString());
                    componentCache.add(component);

                    var analysis = violation.getAnalysis();
                    if (analysis != null && analysis.isSuppressed()) {
                        suppressedViolationCache.add(violation);
                    } else {
                        violationCache.add(violation);
                    }
                }
            }
        }

        for (PolicyViolation.Type riskType : PolicyViolation.Type.values()) {
            newViolationsByRiskType.put(riskType, 0);
        }
        for (PolicyViolation violation : violationCache) {
            newViolationsByRiskType.merge(violation.getType(), 1, Integer::sum);
        }

        affectedProjectsCount = affectedProjectViolations.size();
        newViolationsCount = violationCache.size();
        affectedComponentsCount = componentCache.size();
        suppressedNewViolationsCount = suppressedViolationCache.size();
    }

    public Integer getAffectedProjectsCount() {
        return affectedProjectsCount;
    }

    public Integer getNewViolationsCount() {
        return newViolationsCount;
    }

    public Map<PolicyViolation.Type, Integer> getNewViolationsByRiskType() {
        return newViolationsByRiskType;
    }

    public Integer getAffectedComponentsCount() {
        return affectedComponentsCount;
    }

    public Integer getSuppressedNewViolationsCount() {
        return suppressedNewViolationsCount;
    }
}
