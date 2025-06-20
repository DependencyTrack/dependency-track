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

import alpine.persistence.OrderDirection;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import alpine.server.util.DbUtil;
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.GroupedFinding;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class FindingsSearchQueryManager extends QueryManager implements IQueryManager {

    private static final Map<String, String> sortingAttributes = Map.ofEntries(
            Map.entry("vulnerability.vulnId", "\"VULNERABILITY\".\"VULNID\""),
            Map.entry("vulnerability.title", "\"VULNERABILITY\".\"TITLE\""),
            Map.entry("vulnerability.severity", """
                    CASE WHEN "VULNERABILITY"."SEVERITY" = 'UNASSIGNED'
                         THEN 0
                         WHEN "VULNERABILITY"."SEVERITY" = 'LOW'
                         THEN 3
                         WHEN "VULNERABILITY"."SEVERITY" = 'MEDIUM'
                         THEN 6
                         WHEN "VULNERABILITY"."SEVERITY" = 'HIGH'
                         THEN 8
                         WHEN "VULNERABILITY"."SEVERITY" = 'CRITICAL'
                         THEN 10
                         ELSE CASE WHEN "VULNERABILITY"."CVSSV3BASESCORE" IS NOT NULL
                                   THEN "VULNERABILITY"."CVSSV3BASESCORE"
                                   ELSE "VULNERABILITY"."CVSSV2BASESCORE"
                              END
                    END
                    """),
            Map.entry("attribution.analyzerIdentity", "\"FINDINGATTRIBUTION\".\"ANALYZERIDENTITY\""),
            Map.entry("vulnerability.published", "\"VULNERABILITY\".\"PUBLISHED\""),
            Map.entry("vulnerability.cvssV2BaseScore", "\"VULNERABILITY\".\"CVSSV2BASESCORE\""),
            Map.entry("vulnerability.cvssV3BaseScore", "\"VULNERABILITY\".\"CVSSV3BASESCORE\""),
            Map.entry("component.projectName", "concat(\"PROJECT\".\"NAME\", ' ', \"PROJECT\".\"VERSION\")"),
            Map.entry("component.name", "\"COMPONENT\".\"NAME\""),
            Map.entry("component.version", "\"COMPONENT\".\"VERSION\""),
            Map.entry("analysis.state", "\"ANALYSIS\".\"STATE\""),
            Map.entry("analysis.isSuppressed", "\"ANALYSIS\".\"SUPPRESSED\""),
            Map.entry("attribution.attributedOn", "\"FINDINGATTRIBUTION\".\"ATTRIBUTED_ON\""),
            Map.entry("vulnerability.affectedProjectCount", "COUNT(DISTINCT \"PROJECT\".\"ID\")")
    );

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    FindingsSearchQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    FindingsSearchQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a List of all Finding objects filtered by ACL and other optional filters.
     * @param filters        determines the filters to apply on the list of Finding objects
     * @param showSuppressed determines if suppressed vulnerabilities should be included or not
     * @param showInactive   determines if inactive projects should be included or not
     * @return a List of Finding objects
     */
    public PaginatedResult getAllFindings(final Map<String, String> filters, final boolean showSuppressed, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        Map<String, Object> params = new HashMap<>();
        if (!showInactive) {
            queryFilter.append(" WHERE (\"PROJECT\".\"ACTIVE\" = :active OR \"PROJECT\".\"ACTIVE\" IS NULL)");
            params.put("active", true);
        }
        if (!showSuppressed) {
            if (queryFilter.isEmpty()) {
                queryFilter.append(" WHERE ");
            } else {
                queryFilter.append(" AND ");
            }
            queryFilter.append("(\"ANALYSIS\".\"SUPPRESSED\" = :showSuppressed OR \"ANALYSIS\".\"SUPPRESSED\" IS NULL)");
            params.put("showSuppressed", false);
        }
        processFilters(filters, queryFilter, params, false);
        final Query<Object[]> query = pm.newQuery(Query.SQL, Finding.QUERY_ALL_FINDINGS + queryFilter + (this.orderBy != null ? " ORDER BY " + sortingAttributes.get(this.orderBy) + " " + (this.orderDirection == OrderDirection.DESCENDING ? " DESC" : "ASC") : ""));
        PaginatedResult result = new PaginatedResult();
        query.setNamedParameters(params);
        final List<Object[]> totalList = query.executeList();
        result.setTotal(totalList.size());
        final List<Object[]> list = totalList.subList(this.pagination.getOffset(), Math.min(this.pagination.getOffset() + this.pagination.getLimit(), totalList.size()));
        final List<Finding> findings = new ArrayList<>();
        for (final Object[] o : list) {
            final Finding finding = new Finding(UUID.fromString((String) o[29]), o);
            final Component component = getObjectByUuid(Component.class, (String) finding.getComponent().get("uuid"));
            final Vulnerability vulnerability = getObjectByUuid(Vulnerability.class, (String) finding.getVulnerability().get("uuid"));
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
        result.setObjects(findings);
        return result;
    }

    /**
     * Returns a List of all Finding objects filtered by ACL and other optional filters. The resulting list is grouped by vulnerability.
     * @param filters      determines the filters to apply on the list of Finding objects
     * @param showInactive determines if inactive projects should be included or not
     * @return a List of Finding objects
     */
    public PaginatedResult getAllFindingsGroupedByVulnerability(final Map<String, String> filters, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        Map<String, Object> params = new HashMap<>();
        if (!showInactive) {
            queryFilter.append(" WHERE (\"PROJECT\".\"ACTIVE\" = :active OR \"PROJECT\".\"ACTIVE\" IS NULL)");
            params.put("active", true);
        }
        processFilters(filters, queryFilter, params, true);
        final Query<Object[]> query = pm.newQuery(Query.SQL, GroupedFinding.QUERY + queryFilter + (this.orderBy != null ? " ORDER BY " + sortingAttributes.get(this.orderBy) + " " + (this.orderDirection == OrderDirection.DESCENDING ? " DESC" : "ASC") : ""));
        PaginatedResult result = new PaginatedResult();
        query.setNamedParameters(params);
        final List<Object[]> totalList = query.executeList();
        result.setTotal(totalList.size());
        final List<Object[]> list = totalList.subList(this.pagination.getOffset(), Math.min(this.pagination.getOffset() + this.pagination.getLimit(), totalList.size()));
        final List<GroupedFinding> findings = new ArrayList<>();
        for (Object[] o : list) {
            final GroupedFinding finding = new GroupedFinding(o);
            findings.add(finding);
        }
        result.setObjects(findings);
        return result;
    }

    private void processFilters(Map<String, String> filters, StringBuilder queryFilter, Map<String, Object> params, boolean isGroupedByVulnerabilities) {
        for (String filter : filters.keySet()) {
            switch (filter) {
                case "severity" ->
                        processArrayFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"SEVERITY\"");
                case "analysisStatus" ->
                        processArrayFilter(queryFilter, params, filter, filters.get(filter), "\"ANALYSIS\".\"STATE\"");
                case "vendorResponse" ->
                        processArrayFilter(queryFilter, params, filter, filters.get(filter), "\"ANALYSIS\".\"RESPONSE\"");
                case "publishDateFrom" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"PUBLISHED\"", true, true, false);
                case "publishDateTo" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"PUBLISHED\"", false, true, false);
                case "attributedOnDateFrom" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"FINDINGATTRIBUTION\".\"ATTRIBUTED_ON\"", true, true, false);
                case "attributedOnDateTo" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"FINDINGATTRIBUTION\".\"ATTRIBUTED_ON\"", false, true, false);
                case "textSearchField" ->
                        processInputFilter(queryFilter, params, filter, filters.get(filter), filters.get("textSearchInput"));
                case "cvssv2From" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"CVSSV2BASESCORE\"", true, false, false);
                case "cvssv2To" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"CVSSV2BASESCORE\"", false, false, false);
                case "cvssv3From" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"CVSSV3BASESCORE\"", true, false, false);
                case "cvssv3To" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "\"VULNERABILITY\".\"CVSSV3BASESCORE\"", false, false, false);
            }
        }
        preprocessACLs(queryFilter, params);
        if (isGroupedByVulnerabilities) {
            queryFilter.append("""
                    GROUP BY "VULNERABILITY"."ID"
                           , "VULNERABILITY"."SOURCE"
                           , "VULNERABILITY"."VULNID"
                           , "VULNERABILITY"."TITLE"
                           , "VULNERABILITY"."SEVERITY"
                           , "VULNERABILITY"."CVSSV2BASESCORE"
                           , "VULNERABILITY"."CVSSV3BASESCORE"
                           , "VULNERABILITY"."OWASPRRLIKELIHOODSCORE"
                           , "VULNERABILITY"."OWASPRRTECHNICALIMPACTSCORE"
                           , "VULNERABILITY"."OWASPRRBUSINESSIMPACTSCORE"
                           , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                           , "VULNERABILITY"."PUBLISHED"
                           , "VULNERABILITY"."CWES"
                    """);
            StringBuilder aggregateFilter = new StringBuilder();
            processAggregateFilters(filters, aggregateFilter, params);
            queryFilter.append(aggregateFilter);
        }
    }

    private void processAggregateFilters(Map<String, String> filters, StringBuilder queryFilter, Map<String, Object> params) {
        for (String filter : filters.keySet()) {
            switch (filter) {
                case "occurrencesFrom" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "COUNT(DISTINCT \"PROJECT\".\"ID\")", true, false, true);
                case "occurrencesTo" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "COUNT(DISTINCT \"PROJECT\".\"ID\")", false, false, true);
            }
        }
    }

    private void processArrayFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String column) {
        if (filter != null && !filter.isEmpty()) {
            if (queryFilter.isEmpty()) {
                queryFilter.append(" WHERE (");
            } else {
                queryFilter.append(" AND (");
            }
            String[] filters = filter.split(",");
            for (int i = 0, length = filters.length; i < length; i++) {
                queryFilter.append(column).append(" = :").append(paramName).append(i);
                params.put(paramName + i, filters[i].toUpperCase());
                if (filters[i].equals("NOT_SET") && (paramName.equals("analysisStatus") || paramName.equals("vendorResponse"))) {
                    queryFilter.append(" OR ").append(column).append(" IS NULL");
                }
                if (i < length - 1) {
                    queryFilter.append(" OR ");
                }
            }
            queryFilter.append(")");
        }
    }

    private void processRangeFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String column, boolean fromValue, boolean isDate, boolean isAggregateFilter) {
        if (filter != null && !filter.isEmpty()) {
            if (queryFilter.isEmpty()) {
                queryFilter.append(isAggregateFilter ? " HAVING (" : " WHERE (");
            } else {
                queryFilter.append(" AND (");
            }
            String value = filter;
            if (DbUtil.isPostgreSQL()) {
                queryFilter.append(column).append(fromValue ? " >= " : " <= ");
                if (isDate) {
                    queryFilter.append("TO_TIMESTAMP(:").append(paramName).append(", 'YYYY-MM-DD HH24:MI:SS')");
                    value += (fromValue ? " 00:00:00" : " 23:59:59");
                } else {
                    queryFilter.append("CAST(:").append(paramName).append(" AS NUMERIC)");
                }
            } else {
                queryFilter.append(column).append(fromValue ? " >= :" : " <= :").append(paramName);
                if (isDate) {
                    value += (fromValue ? " 00:00:00" : " 23:59:59");
                }
            }
            params.put(paramName, value);
            queryFilter.append(")");
        }
    }

    private void processAggregatedDateRangeFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String column, boolean fromValue, boolean isMin) {
        if (filter != null && !filter.isEmpty()) {
            if (queryFilter.isEmpty()) {
                queryFilter.append(" HAVING (");
            } else {
                queryFilter.append(isMin ? " AND (" : " OR ");
            }
            if (DbUtil.isPostgreSQL()) {
                queryFilter.append(column).append(fromValue ? " >= " : " <= ");
                queryFilter.append("TO_TIMESTAMP(:").append(paramName).append(", 'YYYY-MM-DD HH24:MI:SS')");
            } else {
                queryFilter.append(column).append(fromValue ? " >= :" : " <= :").append(paramName);
            }
            params.put(paramName, filter + (fromValue ? " 00:00:00" : " 23:59:59"));
            if (!isMin) {
                queryFilter.append(")");
            }
        }
    }

    private void processInputFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String input) {
        if (filter != null && !filter.isEmpty() && input != null && !input.isEmpty()) {
            if (queryFilter.isEmpty()) {
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
                    case "PROJECT_NAME" ->
                            queryFilter.append("concat(\"PROJECT\".\"NAME\", ' ', \"PROJECT\".\"VERSION\")");
                }
                queryFilter.append(" LIKE :").append(paramName);
                if (i < length - 1) {
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
        if (queryFilter.isEmpty()) {
            queryFilter.append(" WHERE ");
        } else {
            queryFilter.append(" AND ");
        }

        final Map.Entry<String, Map<String, Object>> projectAclConditionAndParams = getProjectAclSqlCondition();
        queryFilter.append(projectAclConditionAndParams.getKey()).append(" ");
        params.putAll(projectAclConditionAndParams.getValue());
    }
}
