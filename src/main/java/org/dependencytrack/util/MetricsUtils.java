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
import java.util.TreeMap;
import java.util.stream.Collectors;

public final class MetricsUtils {
    
    private MetricsUtils() {}

    /**
     * Sum project metrics
     * Assumes projects metrics are sorted by first occurence
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

        // Pass 4 output results
        final var results = countersMap.values().stream()
            .map(c -> c.createPortfolioMetrics())
            .collect(Collectors.toList());
        return results;
    }
}
