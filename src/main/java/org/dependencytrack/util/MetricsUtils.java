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
package org.dependencytrack.util;

import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.tasks.metrics.Counters;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;
import java.util.TreeMap;

public final class MetricsUtils {
    
    private MetricsUtils() {}

    /**
     * Sum project metrics
     * @param projectMetrics List of project metrics to sum
     * @param isSorted Pass true if project metrics is already sorted by getFirstOccurrence date
     */
    public static List<PortfolioMetrics> sum(List<ProjectMetrics> projectMetrics, boolean isSorted) {
        // Pass 1 rearrange by project O(n)
        final var dateSet = new HashSet<Date>();
        final var projectsMap = new HashMap<Long, List<ProjectMetrics>>();
        for (final ProjectMetrics pm : projectMetrics) {
            final Long projectId = pm.getProject().getId();
            List<ProjectMetrics> metrics = projectsMap.getOrDefault(projectId, null);
            if (metrics == null) {
                metrics = new ArrayList<ProjectMetrics>();
                projectsMap.put(projectId, metrics);
            }
            metrics.add(pm);
            dateSet.add(pm.getFirstOccurrence());
            dateSet.add(pm.getLastOccurrence());
        }

        // Pass 2 prepare counters to hold results O(n*log(n))
        final var countersMap = new TreeMap<Date, Counters>();
        dateSet.forEach(d -> countersMap.put(d, new Counters(d)));

        // Pass 3 dispatch results by date
        for (final var list : projectsMap.values()) {
            if (list == null || list.size() == 0) {
                continue;
            }

            if (!isSorted) {
                // O(n*log(n))
                Collections.sort(list, (pm1, pm2) -> pm1.getFirstOccurrence().compareTo(pm2.getFirstOccurrence()));
            }

            int index = -1;
            ProjectMetrics metrics = null;
            
            for (final var kv : countersMap.entrySet()) {
                final var date = kv.getKey();
                final var counters = kv.getValue();

                if (index + 1 < list.size()
                    && list.get(index+1).getFirstOccurrence().equals(date)) {
                    
                    index++;
                    metrics = list.get(index);
                }

                if (metrics == null) {
                    continue;
                }

                add(counters, metrics);
            }
        }

        // Pass 4 output results
        final var results = countersMap.values().stream()
            .map(c -> c.createPortfolioMetrics())
            .collect(Collectors.toList());
        return results;
    }

    public static void add(Counters counters, Counters componentCounters) {
        counters.critical += componentCounters.critical;
        counters.high += componentCounters.high;
        counters.medium += componentCounters.medium;
        counters.low += componentCounters.low;
        counters.unassigned += componentCounters.unassigned;
        counters.vulnerabilities += componentCounters.vulnerabilities;

        counters.findingsTotal += componentCounters.findingsTotal;
        counters.findingsAudited += componentCounters.findingsAudited;
        counters.findingsUnaudited += componentCounters.findingsUnaudited;
        counters.suppressions += componentCounters.suppressions;
        counters.inheritedRiskScore = Metrics.inheritedRiskScore(counters.critical, counters.high, counters.medium, counters.low, counters.unassigned);

        counters.components++;
        if (componentCounters.vulnerabilities > 0) {
            counters.vulnerableComponents += 1;
        }

        counters.policyViolationsFail += componentCounters.policyViolationsFail;
        counters.policyViolationsWarn += componentCounters.policyViolationsWarn;
        counters.policyViolationsInfo += componentCounters.policyViolationsInfo;
        counters.policyViolationsTotal += componentCounters.policyViolationsTotal;
        counters.policyViolationsAudited += componentCounters.policyViolationsAudited;
        counters.policyViolationsUnaudited += componentCounters.policyViolationsUnaudited;
        counters.policyViolationsSecurityTotal += componentCounters.policyViolationsSecurityTotal;
        counters.policyViolationsSecurityAudited += componentCounters.policyViolationsSecurityAudited;
        counters.policyViolationsSecurityUnaudited += componentCounters.policyViolationsSecurityUnaudited;
        counters.policyViolationsLicenseTotal += componentCounters.policyViolationsLicenseTotal;
        counters.policyViolationsLicenseAudited += componentCounters.policyViolationsLicenseAudited;
        counters.policyViolationsLicenseUnaudited += componentCounters.policyViolationsLicenseUnaudited;
        counters.policyViolationsOperationalTotal += componentCounters.policyViolationsOperationalTotal;
        counters.policyViolationsOperationalAudited += componentCounters.policyViolationsOperationalAudited;
        counters.policyViolationsOperationalUnaudited += componentCounters.policyViolationsOperationalUnaudited;
    }

    public static void add(Counters counters, ProjectMetrics metrics) {
        counters.critical += metrics.getCritical();
        counters.high += metrics.getHigh();
        counters.medium += metrics.getMedium();
        counters.low += metrics.getLow();
        counters.unassigned += metrics.getUnassigned();
        counters.vulnerabilities += metrics.getVulnerabilities();

        counters.findingsTotal += metrics.getFindingsTotal();
        counters.findingsAudited += metrics.getFindingsAudited();
        counters.findingsUnaudited += metrics.getFindingsUnaudited();
        counters.suppressions += metrics.getSuppressed();
        counters.inheritedRiskScore = Metrics.inheritedRiskScore(counters.critical, counters.high, counters.medium, counters.low, counters.unassigned);

        counters.projects++;
        if (metrics.getVulnerabilities() > 0) {
            counters.vulnerableProjects++;
        }
        counters.components += metrics.getComponents();
        counters.vulnerableComponents += metrics.getVulnerableComponents();

        counters.policyViolationsFail += metrics.getPolicyViolationsFail();
        counters.policyViolationsWarn += metrics.getPolicyViolationsWarn();
        counters.policyViolationsInfo += metrics.getPolicyViolationsInfo();
        counters.policyViolationsTotal += metrics.getPolicyViolationsTotal();
        counters.policyViolationsAudited += metrics.getPolicyViolationsAudited();
        counters.policyViolationsUnaudited += metrics.getPolicyViolationsUnaudited();
        counters.policyViolationsSecurityTotal += metrics.getPolicyViolationsSecurityTotal();
        counters.policyViolationsSecurityAudited += metrics.getPolicyViolationsSecurityAudited();
        counters.policyViolationsSecurityUnaudited += metrics.getPolicyViolationsSecurityUnaudited();
        counters.policyViolationsLicenseTotal += metrics.getPolicyViolationsLicenseTotal();
        counters.policyViolationsLicenseAudited += metrics.getPolicyViolationsLicenseAudited();
        counters.policyViolationsLicenseUnaudited += metrics.getPolicyViolationsLicenseUnaudited();
        counters.policyViolationsOperationalTotal += metrics.getPolicyViolationsOperationalTotal();
        counters.policyViolationsOperationalAudited += metrics.getPolicyViolationsOperationalAudited();
        counters.policyViolationsOperationalUnaudited += metrics.getPolicyViolationsOperationalUnaudited();
    }

}
