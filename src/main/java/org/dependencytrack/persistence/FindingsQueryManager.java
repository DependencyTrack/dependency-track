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
package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.model.ApiKey;
import alpine.model.Team;
import alpine.model.UserPrincipal;
import alpine.resources.AlpineRequest;
import alpine.server.util.DbUtil;
import com.github.packageurl.PackageURL;
import org.datanucleus.api.jdo.JDOQuery;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.GroupedFinding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.RepositoryMetaComponent;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;

public class FindingsQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(FindingsQueryManager.class);

    public static final String QUERY_ACL_1 = """
            "DESCENDANTS" ("ID", "NAME") AS
                            (SELECT "PROJECT"."ID",
                            "PROJECT"."NAME"
                             FROM "PROJECT"
            """;

    public static final String QUERY_ACL_2 = """
            UNION ALL
            SELECT "CHILD"."ID",
                            "CHILD"."NAME"
                            FROM "PROJECT" "CHILD"
                                 JOIN "DESCENDANTS"
                                     ON "DESCENDANTS"."ID" = "CHILD"."PARENT_PROJECT_ID")
                        SELECT "DESCENDANTS"."ID", "DESCENDANTS"."NAME" FROM "DESCENDANTS"
            """;

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
    @SuppressWarnings("unchecked")
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
        final Query<Object[]> query = pm.newQuery(JDOQuery.SQL_QUERY_LANGUAGE, Finding.QUERY);
        query.setParameters(project.getId());
        final List<Object[]> list = query.executeList();
        final List<Finding> findings = new ArrayList<>();
        for (final Object[] o: list) {
            final Finding finding = new Finding(project.getUuid(), o);
            final Component component = getObjectByUuid(Component.class, (String)finding.getComponent().get("uuid"));
            final Vulnerability vulnerability = getObjectByUuid(Vulnerability.class, (String)finding.getVulnerability().get("uuid"));
            final Analysis analysis = getAnalysis(component, vulnerability);
            final List<VulnerabilityAlias> aliases = detach(getVulnerabilityAliases(vulnerability));
            finding.addVulnerabilityAliases(aliases);
            if (includeSuppressed || analysis == null || !analysis.isSuppressed()) { // do not add globally suppressed findings
                // These are CLOB fields. Handle these here so that database-specific deserialization doesn't need to be performed (in Finding)
                finding.getVulnerability().put("description", vulnerability.getDescription());
                finding.getVulnerability().put("recommendation", vulnerability.getRecommendation());
                final PackageURL purl = component.getPurl();
                if (purl != null) {
                    final RepositoryType type = RepositoryType.resolve(purl);
                    if (RepositoryType.UNSUPPORTED != type) {
                        final RepositoryMetaComponent repoMetaComponent = getRepositoryMetaComponent(type, purl.getNamespace(), purl.getName());
                        if (repoMetaComponent != null) {
                            finding.getComponent().put("latestVersion", repoMetaComponent.getLatestVersion());
                        }
                    }
                }
                findings.add(finding);
            }
        }
        return findings;
    }

    /**
     * Returns a List of all Finding objects filtered by ACL and other optional filters.
     * @param filters determines the filters to apply on the list of Finding objects
     * @param showSuppressed determines if suppressed vulnerabilities should be included or not
     * @param showInactive determines if inactive projects should be included or not
     * @return a List of Finding objects
     */
    public List<Finding> getAllFindings(final Map<String, String> filters, final boolean showSuppressed, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        Map<String, Object> params = new HashMap<>();
        if (showInactive) {
            queryFilter.append(" WHERE (\"PROJECT\".\"ACTIVE\" = :active OR \"PROJECT\".\"ACTIVE\" IS NULL)");
            params.put("active", true);
        }
        if (!showSuppressed) {
            if (queryFilter.length() == 0) {
                queryFilter.append(" WHERE ");
            } else {
                queryFilter.append(" AND ");
            }
            queryFilter.append("(\"ANALYSIS\".\"SUPPRESSED\" = :showSuppressed OR \"ANALYSIS\".\"SUPPRESSED\" IS NULL)");
            params.put("showSuppressed", false);
        }
        processFilters(filters, queryFilter, params, false);
        final Query<Object[]> query = pm.newQuery(JDOQuery.SQL_QUERY_LANGUAGE, Finding.QUERY_ALL_FINDINGS + queryFilter);
        query.setNamedParameters(params);
        final List<Object[]> list = query.executeList();
        final List<Finding> findings = new ArrayList<>();
        for (final Object[] o: list) {
            final Finding finding = new Finding(UUID.fromString((String) o[29]), o);
            final Component component = getObjectByUuid(Component.class, (String)finding.getComponent().get("uuid"));
            final Vulnerability vulnerability = getObjectByUuid(Vulnerability.class, (String)finding.getVulnerability().get("uuid"));
            final Analysis analysis = getAnalysis(component, vulnerability);
            final List<VulnerabilityAlias> aliases = detach(getVulnerabilityAliases(vulnerability));
            aliases.forEach(alias -> alias.setUuid(null));
            finding.getVulnerability().put("aliases", aliases);
            // These are CLOB fields. Handle these here so that database-specific deserialization doesn't need to be performed (in Finding)
            finding.getVulnerability().put("description", vulnerability.getDescription());
            finding.getVulnerability().put("recommendation", vulnerability.getRecommendation());
            final PackageURL purl = component.getPurl();
            if (purl != null) {
                final RepositoryType type = RepositoryType.resolve(purl);
                if (RepositoryType.UNSUPPORTED != type) {
                    final RepositoryMetaComponent repoMetaComponent = getRepositoryMetaComponent(type, purl.getNamespace(), purl.getName());
                    if (repoMetaComponent != null) {
                        finding.getComponent().put("latestVersion", repoMetaComponent.getLatestVersion());
                    }
                }

            }
            findings.add(finding);
        }
        return findings;
    }

    /**
     * Returns a List of all Finding objects filtered by ACL and other optional filters. The resulting list is grouped by vulnerability.
     * @param filters determines the filters to apply on the list of Finding objects
     * @param showInactive determines if inactive projects should be included or not
     * @return a List of Finding objects
     */
    public List<GroupedFinding> getAllFindingsGroupedByVulnerability(final Map<String, String> filters, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        Map<String, Object> params = new HashMap<>();
        if (showInactive) {
            queryFilter.append(" WHERE (\"PROJECT\".\"ACTIVE\" = :active OR \"PROJECT\".\"ACTIVE\" IS NULL)");
            params.put("active", true);
        }
        processFilters(filters, queryFilter, params, true);
        final Query<Object[]> query = pm.newQuery(JDOQuery.SQL_QUERY_LANGUAGE, GroupedFinding.QUERY + queryFilter);
        query.setNamedParameters(params);
        final List<Object[]> list = query.executeList();
        final List<GroupedFinding> findings = new ArrayList<>();
        for (Object[] o : list) {
            final GroupedFinding finding = new GroupedFinding(o);
            findings.add(finding);
        }
        return findings;
    }

    private void processFilters(Map<String, String> filters, StringBuilder queryFilter, Map<String, Object> params, boolean isGroupedByVulnerabilities) {
        for (String filter : filters.keySet()) {
            switch (filter) {
                case "severity" -> processArrayFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"SEVERITY\"");
                case "analysisStatus" -> processArrayFilter(queryFilter, params, filter, filters.get(filter), "\"ANALYSIS\".\"STATE\"");
                case "vendorResponse" -> processArrayFilter(queryFilter, params, filter, filters.get(filter), "\"ANALYSIS\".\"RESPONSE\"");
                case "publishDateFrom" -> processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"PUBLISHED\"", true, true, false);
                case "publishDateTo" -> processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"PUBLISHED\"", false, true, false);
                case "attributedOnDateFrom" -> processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"FINDINGATTRIBUTION\".\"ATTRIBUTED_ON\"", true, true, false);
                case "attributedOnDateTo" -> processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"FINDINGATTRIBUTION\".\"ATTRIBUTED_ON\"", false, true, false);
                case "textSearchField" -> processInputFilter(queryFilter, params, filter, filters.get(filter), filters.get("textSearchInput"));
                case "cvssFrom" -> processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"CVSSV3BASESCORE\"", true, false, false);
                case "cvssTo" -> processRangeFilter(queryFilter, params,filter, filters.get(filter), "\"VULNERABILITY\".\"CVSSV3BASESCORE\"", false, false, false);
            }
        }
        preprocessACLs(queryFilter, params);
        if (isGroupedByVulnerabilities) {
            queryFilter.append(" GROUP BY \"VULNERABILITY\".\"ID\"");
            StringBuilder aggregateFilter = new StringBuilder();
            processAggregateFilters(filters, aggregateFilter, params);
            queryFilter.append(aggregateFilter);
        }
    }

    private void processAggregateFilters(Map<String, String> filters, StringBuilder queryFilter, Map<String, Object> params) {
        for (String filter : filters.keySet()) {
            switch (filter) {
                case "occurrencesFrom" -> processRangeFilter(queryFilter, params, filter, filters.get(filter), "COUNT(DISTINCT \"PROJECT\".\"ID\")", true, false, true);
                case "occurrencesTo" -> processRangeFilter(queryFilter, params, filter, filters.get(filter), "COUNT(DISTINCT \"PROJECT\".\"ID\")", false, false, true);
                case "aggregatedAttributedOnDateFrom" -> {
                    processAggregatedDateRangeFilter(queryFilter, params, filter, filters.get(filter), "MIN(\"AFFECTEDVERSIONATTRIBUTION\".\"FIRST_SEEN\")", true, true);
                    processAggregatedDateRangeFilter(queryFilter, params, filter, filters.get(filter), "MAX(\"AFFECTEDVERSIONATTRIBUTION\".\"LAST_SEEN\")", true, false);
                }
                case "aggregatedAttributedOnDateTo" -> {
                    processAggregatedDateRangeFilter(queryFilter, params, filter, filters.get(filter), "MIN(\"AFFECTEDVERSIONATTRIBUTION\".\"FIRST_SEEN\")", false, true);
                    processAggregatedDateRangeFilter(queryFilter, params, filter, filters.get(filter), "MAX(\"AFFECTEDVERSIONATTRIBUTION\".\"LAST_SEEN\")", false, false);
                }
            }
        }
    }

    private void processArrayFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String column) {
        if (filter != null && !filter.isEmpty()) {
            if (queryFilter.length() == 0) {
                queryFilter.append(" WHERE (");
            } else {
                queryFilter.append(" AND (");
            }
            String[] filters = filter.split(",");
            for (int i = 0, length = filters.length; i < length; i++) {
                queryFilter.append(column).append(" = :").append(paramName).append(i);
                params.put(paramName + i, filters[i].toUpperCase());
                if (i < length-1) {
                    queryFilter.append(" OR ");
                }
            }
            queryFilter.append(")");
        }
    }

    private void processRangeFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String column, boolean fromValue, boolean isDate, boolean isAggregateFilter) {
        if (filter != null && !filter.isEmpty()) {
            if (queryFilter.length() == 0) {
                queryFilter.append(isAggregateFilter ? " HAVING (" : " WHERE (");
            } else {
                queryFilter.append(" AND (");
            }
            queryFilter.append(column).append(fromValue ? " >= :" : " <= :").append(paramName);
            String value = filter;
            if (isDate) {
                value += (fromValue ? " 00:00:00" : " 23:59:59");
            }
            params.put(paramName, value);
            queryFilter.append(")");
        }
    }

    private void processAggregatedDateRangeFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String column, boolean fromValue, boolean isMin) {
        if (filter != null && !filter.isEmpty()) {
            if (queryFilter.length() == 0) {
                queryFilter.append(" HAVING (");
            } else {
                queryFilter.append(isMin ? " AND (" : " OR ");
            }
            queryFilter.append(column).append(fromValue ? " >= :" : " <= :").append(paramName);
            String value = filter;
            value += (fromValue ? " 00:00:00" : " 23:59:59");
            params.put(paramName, value);
            if (!isMin) {
                queryFilter.append(")");
            }
        }
    }

    private void processInputFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String input) {
        if (filter != null && !filter.isEmpty() && input != null && !input.isEmpty()) {
            if (queryFilter.length() == 0) {
                queryFilter.append(" WHERE (");
            } else {
                queryFilter.append(" AND (");
            }
            String[] filters = filter.split(",");
            for (int i = 0, length = filters.length; i < length; i++) {
                switch (filters[i].toUpperCase()) {
                    case "VULNERABILITY_ID" -> queryFilter.append("\"VULNERABILITY\".\"VULNID\"");
                    case "VULNERABILITY_TITLE" -> queryFilter.append("\"VULNERABILITY\".\"TITLE\"");
                    case "COMPONENT_NAME" -> queryFilter.append("\"COMPONENT\".\"NAME\"");
                    case "COMPONENT_VERSION" -> queryFilter.append("\"COMPONENT\".\"VERSION\"");
                    case "PROJECT_NAME" -> queryFilter.append("concat(\"PROJECT\".\"NAME\", ' ', \"PROJECT\".\"VERSION\")");
                }
                queryFilter.append(" LIKE :").append(paramName);
                if (i < length-1) {
                    queryFilter.append(" OR ");
                }
            }
            if (filters.length > 0) {
                params.put(paramName, "%" + input + "%");
            }
            queryFilter.append(")");
        }
    }

    private void preprocessACLs(StringBuilder queryFilter, final Map<String, Object> params) {
        if (super.principal != null && isEnabled(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED)) {
            final List<Team> teams;
            if (super.principal instanceof UserPrincipal) {
                final UserPrincipal userPrincipal = ((UserPrincipal) super.principal);
                teams = userPrincipal.getTeams();
                if (super.hasAccessManagementPermission(userPrincipal)) {
                    return;
                }
            } else {
                final ApiKey apiKey = ((ApiKey) super.principal);
                teams = apiKey.getTeams();
                if (super.hasAccessManagementPermission(apiKey)) {
                    return;
                }
            }

            // Query every project that the teams have access to
            final Map<String, Object> tempParams = new HashMap<>();
            final Query<Project> queryAclProjects = pm.newQuery(Project.class);
            if (teams != null && teams.size() > 0) {
                final StringBuilder stringBuilderAclProjects = new StringBuilder();
                for (int i = 0, teamsSize = teams.size(); i < teamsSize; i++) {
                    final Team team = super.getObjectById(Team.class, teams.get(i).getId());
                    stringBuilderAclProjects.append(" accessTeams.contains(:team").append(i).append(") ");
                    tempParams.put("team" + i, team);
                    if (i < teamsSize - 1) {
                        stringBuilderAclProjects.append(" || ");
                    }
                }
                queryAclProjects.setFilter(stringBuilderAclProjects.toString());
            } else {
                params.put("false", false);
                if (queryFilter != null && !queryFilter.isEmpty()) {
                    queryFilter.append(" AND :false");
                } else {
                    queryFilter.append("WHERE :false");
                }
            }
            List<Project> result = (List<Project>) queryAclProjects.executeWithMap(tempParams);
            // Query the descendants of the projects that the teams have access to
            if (result != null && !result.isEmpty()) {
                final StringBuilder stringBuilderDescendants = new StringBuilder();
                final List<Long> parameters = new ArrayList<>();
                stringBuilderDescendants.append("WHERE");
                int i = 0, teamSize = result.size();
                for (Project project : result) {
                    stringBuilderDescendants.append(" \"ID\" = ?").append(" ");
                    parameters.add(project.getId());
                    if (i < teamSize - 1) {
                        stringBuilderDescendants.append(" OR");
                    }
                    i++;
                }
                stringBuilderDescendants.append("\n");
                final List<Long> results = new ArrayList<>();

                // Querying the descendants of projects requires a CTE (Common Table Expression), which needs to be at the top-level of the query for Microsoft SQL Server.
                // Because of JDO, queries are only allowed to start with "SELECT", so the "WITH" clause for the CTE in MSSQL cannot be at top level.
                // Activating the JDO property that queries don't have to start with "SELECT" does not help in this case, because JDO queries that do not start with "SELECT" only return "true", so no data can be fetched this way.
                // To circumvent this problem, the query is executed via the direct connection to the database and not via JDO.
                Connection connection = null;
                PreparedStatement preparedStatement = null;
                ResultSet rs = null;
                try {
                    connection = (Connection) pm.getDataStoreConnection();
                    if (DbUtil.isMssql() || DbUtil.isOracle()) { // Microsoft SQL Server and Oracle DB already imply the "RECURSIVE" keyword in the "WITH" clause, therefore it is not needed in the query
                        preparedStatement = connection.prepareStatement("WITH " + QUERY_ACL_1 + stringBuilderDescendants + QUERY_ACL_2);
                    } else { // Other Databases need the "RECURSIVE" keyword in the "WITH" clause to correctly execute the query
                        preparedStatement = connection.prepareStatement("WITH RECURSIVE " + QUERY_ACL_1 + stringBuilderDescendants + QUERY_ACL_2);
                    }
                    int j = 1;
                    for (Long id : parameters) {
                        preparedStatement.setLong(j, id);
                        j++;
                    }
                    preparedStatement.execute();
                    rs = preparedStatement.getResultSet();
                    while (rs.next()) {
                        results.add(rs.getLong(1));
                    }
                } catch (Exception e) {
                    LOGGER.error(e.getMessage());
                    params.put("false", false);
                    if (queryFilter != null && !queryFilter.isEmpty()) {
                        queryFilter.append(" AND :false");
                    } else {
                        queryFilter.append("WHERE :false");
                    }
                    return;
                } finally {
                    DbUtil.close(rs);
                    DbUtil.close(preparedStatement);
                    DbUtil.close(connection);
                }

                // Add queried projects and descendants to the input filter of the query
                if (results != null && !results.isEmpty()) {
                    final StringBuilder stringBuilderInputFilter = new StringBuilder();
                    int j = 0;
                    int resultSize = results.size();
                    for (Long id : results) {
                        stringBuilderInputFilter.append(" \"PROJECT\".\"ID\" = :id").append(j);
                        params.put("id" + j, id);
                        if (j < resultSize - 1) {
                            stringBuilderInputFilter.append(" OR ");
                        }
                        j++;
                    }
                    if (queryFilter != null && !queryFilter.isEmpty()) {
                        queryFilter.append(" AND (").append(stringBuilderInputFilter).append(")");
                    } else {
                        queryFilter.append("WHERE (").append(stringBuilderInputFilter).append(")");
                    }
                }
            } else {
                params.put("false", false);
                if (queryFilter != null && !queryFilter.isEmpty()) {
                    queryFilter.append(" AND :false");
                } else {
                    queryFilter.append("WHERE :false");
                }
            }
        }
    }
}
