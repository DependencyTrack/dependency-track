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
}
