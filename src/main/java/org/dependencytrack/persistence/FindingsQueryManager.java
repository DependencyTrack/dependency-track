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
package org.dependencytrack.persistence;

import alpine.resources.AlpineRequest;
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.VulnIdAndSource;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.persistence.RepositoryQueryManager.RepositoryMetaComponentSearch;
import org.dependencytrack.util.PurlUtil;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class FindingsQueryManager extends QueryManager implements IQueryManager {


    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    FindingsQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    FindingsQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns the number of audited findings for the portfolio.
     * Findings that are suppressed or have been assigned the states {@link AnalysisState#NOT_SET} or {@link AnalysisState#IN_TRIAGE}
     * do not count as audited. Suppressions are tracked separately.
     * @return the total number of analysis decisions
     */
    public long getAuditedCount() {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "analysisState != null && suppressed == false && analysisState != :notSet && analysisState != :inTriage");
        return getCount(query, AnalysisState.NOT_SET, AnalysisState.IN_TRIAGE);
    }

    /**
     * Returns the number of audited findings for the specified Project.
     * Findings that are suppressed or have been assigned the states {@link AnalysisState#NOT_SET} or {@link AnalysisState#IN_TRIAGE}
     * do not count as audited. Suppressions are tracked separately.
     * @param project the Project to retrieve audit counts for
     * @return the total number of analysis decisions for the project
     */
    public long getAuditedCount(Project project) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project && analysisState != null && suppressed == false && analysisState != :notSet && analysisState != :inTriage");
        return getCount(query, project, AnalysisState.NOT_SET, AnalysisState.IN_TRIAGE);
    }

    /**
     * Returns the number of audited findings for the specified Component.
     * Findings that are suppressed or have been assigned the states {@link AnalysisState#NOT_SET} or {@link AnalysisState#IN_TRIAGE}
     * do not count as audited. Suppressions are tracked separately.
     * @param component the Component to retrieve audit counts for
     * @return the total number of analysis decisions for the component
     */
    public long getAuditedCount(Component component) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "component == :component && analysisState != null && suppressed == false && analysisState != :notSet && analysisState != :inTriage");
        return getCount(query, component, AnalysisState.NOT_SET, AnalysisState.IN_TRIAGE);
    }

    /**
     * Returns the number of audited findings for the specified Project / Component.
     * @param project the Project to retrieve audit counts for
     * @param component the Component to retrieve audit counts for
     * @return the total number of analysis decisions for the project / component
     */
    public long getAuditedCount(Project project, Component component) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project && component == :component && analysisState != null && analysisState != :notSet && analysisState != :inTriage");
        return getCount(query, project, component, AnalysisState.NOT_SET, AnalysisState.IN_TRIAGE);
    }

    /**
     * Returns the number of suppressed vulnerabilities for the portfolio.
     * @return the total number of suppressed vulnerabilities
     */
    public long getSuppressedCount() {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "suppressed == true");
        return getCount(query);
    }

    /**
     * Returns the number of suppressed vulnerabilities for the specified Project
     * @param project the Project to retrieve suppressed vulnerabilities of
     * @return the total number of suppressed vulnerabilities for the project
     */
    public long getSuppressedCount(Project project) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project && suppressed == true");
        return getCount(query, project);
    }

    /**
     * Returns the number of suppressed vulnerabilities for the specified Component.
     * @param component the Component to retrieve suppressed vulnerabilities of
     * @return the total number of suppressed vulnerabilities for the component
     */
    public long getSuppressedCount(Component component) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "component == :component && suppressed == true");
        return getCount(query, component);
    }

    /**
     * Returns the number of suppressed vulnerabilities for the specified Project / Component.
     * @param project the Project to retrieve suppressed vulnerabilities of
     * @param component the Component to retrieve suppressed vulnerabilities of
     * @return the total number of suppressed vulnerabilities for the project / component
     */
    public long getSuppressedCount(Project project, Component component) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project && component == :component && suppressed == true");
        return getCount(query, project, component);
    }

    /**
     * Returns a List Analysis for the specified Project.
     * @param project the Project
     * @return a List of Analysis objects, or null if not found
     */
    @SuppressWarnings("unchecked")
    List<Analysis> getAnalyses(Project project) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project");
        return (List<Analysis>) query.execute(project);
    }

    /**
     * Returns a Analysis for the specified Project, Component, and Vulnerability.
     * @param component the Component
     * @param vulnerability the Vulnerability
     * @return a Analysis object, or null if not found
     */
    public Analysis getAnalysis(Component component, Vulnerability vulnerability) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "component == :component && vulnerability == :vulnerability");
        query.setRange(0, 1);
        return singleResult(query.execute(component, vulnerability));
    }

    /**
     * Documents a new analysis. Creates a new Analysis object if one doesn't already exist and appends
     * the specified comment along with a timestamp in the AnalysisComment trail.
     * @param component the Component
     * @param vulnerability the Vulnerability
     * @return an Analysis object
     */
    public Analysis makeAnalysis(Component component, Vulnerability vulnerability, AnalysisState analysisState,
                                 AnalysisJustification analysisJustification, AnalysisResponse analysisResponse,
                                 String analysisDetails, Boolean isSuppressed) {
        return makeAnalysis(component, vulnerability, analysisState, analysisJustification, analysisResponse,
                analysisDetails, isSuppressed, null, null, null, null, null, null);
    }

    public Analysis makeAnalysis(Component component, Vulnerability vulnerability, AnalysisState analysisState,
                                 AnalysisJustification analysisJustification, AnalysisResponse analysisResponse,
                                 String analysisDetails, Boolean isSuppressed,
                                 String riskImpact, String riskLikelihood, String residualRiskImpact,
                                 String residualRiskLikelihood, String riskJustification, String residualRiskJustification) {
        Analysis analysis = getAnalysis(component, vulnerability);
        if (analysis == null) {
            analysis = new Analysis();
            analysis.setComponent(component);
            analysis.setVulnerability(vulnerability);
        }

        // In case we're updating an existing analysis, setting any of the fields
        // to null will wipe them. That is not the expected behavior when an AnalysisRequest
        // has some fields unset (so they're null). If fields are not set, there shouldn't
        // be any modifications to the existing data.
        if (analysisState != null) {
            analysis.setAnalysisState(analysisState);
        }
        if (analysisJustification != null) {
            analysis.setAnalysisJustification(analysisJustification);
        }
        if (analysisResponse != null) {
            analysis.setAnalysisResponse(analysisResponse);
        }
        if (analysisDetails != null) {
            analysis.setAnalysisDetails(analysisDetails);
        }
        if (isSuppressed != null) {
            analysis.setSuppressed(isSuppressed);
        }

        // Risk matrix fields are always updated unconditionally — the frontend sends the full
        // current state on every save (including null when the user explicitly clears a field).
        // Unlike analysisState/isSuppressed (which are omitted from requests that don't touch them),
        // these fields must support being cleared back to null.
        analysis.setRiskImpact(StringUtils.trimToNull(riskImpact));
        analysis.setRiskLikelihood(StringUtils.trimToNull(riskLikelihood));

        // Calculate risk score if both impact and likelihood are set; clear it otherwise
        if (analysis.getRiskImpact() != null && analysis.getRiskLikelihood() != null) {
            analysis.setRiskScore(calculateRiskScore(analysis.getRiskImpact(), analysis.getRiskLikelihood()));
        } else {
            analysis.setRiskScore(null);
        }

        analysis.setResidualRiskImpact(StringUtils.trimToNull(residualRiskImpact));
        analysis.setResidualRiskLikelihood(StringUtils.trimToNull(residualRiskLikelihood));

        // Calculate residual risk score if both impact and likelihood are set; clear it otherwise
        if (analysis.getResidualRiskImpact() != null && analysis.getResidualRiskLikelihood() != null) {
            analysis.setResidualRiskScore(calculateRiskScore(analysis.getResidualRiskImpact(), analysis.getResidualRiskLikelihood()));
        } else {
            analysis.setResidualRiskScore(null);
        }

        analysis.setRiskJustification(StringUtils.trimToNull(riskJustification));
        analysis.setResidualRiskJustification(StringUtils.trimToNull(residualRiskJustification));

        analysis = persist(analysis);
        return getAnalysis(analysis.getComponent(), analysis.getVulnerability());
    }

    /**
     * Adds a new analysis comment to the specified analysis.
     * @param analysis the analysis object to add a comment to
     * @param comment the comment to make
     * @param commenter the name of the principal who wrote the comment
     * @return a new AnalysisComment object
     */
    public AnalysisComment makeAnalysisComment(Analysis analysis, String comment, String commenter) {
        if (analysis == null || comment == null) {
            return null;
        }
        final AnalysisComment analysisComment = new AnalysisComment();
        analysisComment.setAnalysis(analysis);
        analysisComment.setTimestamp(new Date());
        analysisComment.setComment(comment);
        analysisComment.setCommenter(commenter);
        return persist(analysisComment);
    }

    /**
     * Deleted all analysis and comments associated for the specified Component.
     * @param component the Component to delete analysis for
     */
    void deleteAnalysisTrail(Component component) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "component == :component");
        query.deletePersistentAll(component);
    }

    /**
     * Deleted all analysis and comments associated for the specified Project.
     * @param project the Project to delete analysis for
     */
    void deleteAnalysisTrail(Project project) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project");
        query.deletePersistentAll(project);
    }

    /**
     * Returns a List of Finding objects for the specified project.
     * @param project the project to retrieve findings for
     * @return a List of Finding objects
     */
    public List<Finding> getFindings(Project project) {
        return getFindings(project, false);
    }

    /**
     * Returns a List of Finding objects for the specified project.
     * @param project the project to retrieve findings for
     * @param includeSuppressed determines if suppressed vulnerabilities should be included or not
     * @return a List of Finding objects
     */
    @SuppressWarnings("unchecked")
    public List<Finding> getFindings(Project project, boolean includeSuppressed) {
        final Query<Object[]> query = pm.newQuery(Query.SQL, Finding.QUERY);
        query.setNamedParameters(Map.ofEntries(
                Map.entry("projectId", project.getId()),
                Map.entry("includeSuppressed", includeSuppressed),
                // NB: These are required for MSSQL, apparently it doesn't have
                // a native boolean type, or DataNucleus maps booleans to a type
                // that doesn't have boolean semantics. Fun!
                Map.entry("false", false),
                Map.entry("true", true)
        ));
        final List<Object[]> queryResultRows = executeAndCloseList(query);

        final List<Finding> findings = queryResultRows.stream()
                .map(row -> new Finding(project.getUuid(), row))
                .toList();

        final Map<VulnIdAndSource, List<Finding>> findingsByVulnIdAndSource = findings.stream()
                .collect(Collectors.groupingBy(
                        finding -> new VulnIdAndSource(
                                (String) finding.getVulnerability().get("vulnId"),
                                (String) finding.getVulnerability().get("source")
                        )
                ));
        final Map<VulnIdAndSource, List<VulnerabilityAlias>> aliasesByVulnIdAndSource =
                getVulnerabilityAliases(findingsByVulnIdAndSource.keySet());
        for (final VulnIdAndSource vulnIdAndSource : findingsByVulnIdAndSource.keySet()) {
            final List<Finding> affectedFindings = findingsByVulnIdAndSource.get(vulnIdAndSource);
            final List<VulnerabilityAlias> aliases = aliasesByVulnIdAndSource.getOrDefault(vulnIdAndSource, Collections.emptyList());

            for (final Finding finding : affectedFindings) {
                finding.addVulnerabilityAliases(aliases);
            }
        }

        final Map<RepositoryMetaComponentSearch, List<Finding>> findingsByMetaComponentSearch = findings.stream()
                .filter(finding -> finding.getComponent().get("purl") != null)
                .map(finding -> {
                    final PackageURL purl = PurlUtil.silentPurl((String) finding.getComponent().get("purl"));
                    if (purl == null) {
                        return null;
                    }

                    final var repositoryType = RepositoryType.resolve(purl);
                    if (repositoryType == RepositoryType.UNSUPPORTED) {
                        return null;
                    }

                    final var search = new RepositoryMetaComponentSearch(repositoryType, purl.getNamespace(), purl.getName());
                    return Map.entry(search, finding);
                })
                .filter(Objects::nonNull)
                .collect(Collectors.groupingBy(
                        Map.Entry::getKey,
                        Collectors.mapping(Map.Entry::getValue, Collectors.toList())
                ));
        getRepositoryMetaComponents(List.copyOf(findingsByMetaComponentSearch.keySet()))
                .forEach(metaComponent -> {
                    final var search = new RepositoryMetaComponentSearch(metaComponent.getRepositoryType(), metaComponent.getNamespace(), metaComponent.getName());
                    final List<Finding> affectedFindings = findingsByMetaComponentSearch.get(search);
                    if (affectedFindings != null) {
                        for (final Finding finding : affectedFindings) {
                            finding.getComponent().put("latestVersion", metaComponent.getLatestVersion());
                        }
                    }
                });

        return findings;
    }

    /**
     * Calculates the risk score based on the OWASP Risk Rating methodology.
     * @param impact the risk impact value (VERY_LOW, LOW, MEDIUM, HIGH, VERY_HIGH)
     * @param likelihood the risk likelihood value (VERY_LOW, LOW, MEDIUM, HIGH, VERY_HIGH)
     * @return the calculated risk score
     */
    private Double calculateRiskScore(String impact, String likelihood) {
        if (impact == null || likelihood == null) {
            return null;
        }

        // Map risk levels to numeric values (1-5)
        final double impactValue = getRiskValue(impact);
        final double likelihoodValue = getRiskValue(likelihood);

        // Calculate risk score using OWASP formula: (Impact + Likelihood) / 2
        // Result range: 1.0 to 5.0
        return (impactValue + likelihoodValue) / 2.0;
    }

    /**
     * Converts a risk level string to its numeric value.
     * @param riskLevel the risk level (VERY_LOW, LOW, MEDIUM, HIGH, VERY_HIGH)
     * @return the numeric value (1-5)
     */
    private double getRiskValue(String riskLevel) {
        return switch (riskLevel.toUpperCase()) {
            case "VERY_LOW" -> 1.0;
            case "LOW" -> 2.0;
            case "MEDIUM" -> 3.0;
            case "HIGH" -> 4.0;
            case "VERY_HIGH" -> 5.0;
            default -> 3.0; // default to MEDIUM
        };
    }
}
