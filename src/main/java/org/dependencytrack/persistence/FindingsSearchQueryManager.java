package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.model.ApiKey;
import alpine.model.Team;
import alpine.model.UserPrincipal;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import alpine.server.util.DbUtil;
import com.github.packageurl.PackageURL;
import org.datanucleus.api.jdo.JDOQuery;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.GroupedFinding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class FindingsSearchQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(FindingsSearchQueryManager.class);

    private static final Map<String, String> sortingAttributes = Map.ofEntries(
        Map.entry("vulnerability.vulnId", "\"VULNERABILITY\".\"VULNID\""),
        Map.entry("vulnerability.title", "\"VULNERABILITY\".\"TITLE\""),
        Map.entry("vulnerability.severity", """
            CASE WHEN \"VULNERABILITY\".\"SEVERITY\" = 'UNASSIGNED' THEN 0 WHEN \"VULNERABILITY\".\"SEVERITY\" = 'LOW' THEN 3
            WHEN \"VULNERABILITY\".\"SEVERITY\" = 'MEDIUM' THEN 6 WHEN \"VULNERABILITY\".\"SEVERITY\" = 'HIGH' THEN 8
            WHEN \"VULNERABILITY\".\"SEVERITY\" = 'CRITICAL' THEN 10 ELSE 
            CASE WHEN \"VULNERABILITY\".\"CVSSV3BASESCORE\" IS NOT NULL THEN \"VULNERABILITY\".\"CVSSV3BASESCORE\" 
            ELSE \"VULNERABILITY\".\"CVSSV2BASESCORE\" END END
            """),
        Map.entry("attribution.analyzerIdentity", "\"FINDINGATTRIBUTION\".\"ANALYZERIDENTITY\""),
        Map.entry("vulnerability.published", "\"VULNERABILITY\".\"PUBLISHED\""),
        Map.entry("vulnerability.cvssV3BaseScore", "\"VULNERABILITY\".\"CVSSV3BASESCORE\""),
        Map.entry("component.projectName", "concat(\"PROJECT\".\"NAME\", ' ', \"PROJECT\".\"VERSION\")"),
        Map.entry("component.name", "\"COMPONENT\".\"NAME\""),
        Map.entry("component.version", "\"COMPONENT\".\"VERSION\""),
        Map.entry("analysis.state", "\"ANALYSIS\".\"STATE\""),
        Map.entry("analysis.isSuppressed", "\"ANALYSIS\".\"SUPPRESSED\""),
        Map.entry("attribution.attributedOn", "\"FINDINGATTRIBUTION\".\"ATTRIBUTED_ON\""),
        Map.entry("vulnerability.affectedProjectCount", "COUNT(DISTINCT \"PROJECT\".\"ID\")"),
        Map.entry("attribution.firstOccurrence", "MIN(\"AFFECTEDVERSIONATTRIBUTION\".\"FIRST_SEEN\")"),
        Map.entry("attribution.lastOccurrence", "MAX(\"AFFECTEDVERSIONATTRIBUTION\".\"LAST_SEEN\")")
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
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    FindingsSearchQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

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
     * Returns a List of all Finding objects filtered by ACL and other optional filters.
     * @param filters determines the filters to apply on the list of Finding objects
     * @param showSuppressed determines if suppressed vulnerabilities should be included or not
     * @param showInactive determines if inactive projects should be included or not
     * @return a List of Finding objects
     */
    public PaginatedResult getAllFindings(final Map<String, String> filters, final boolean showSuppressed, final boolean showInactive) {
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
        final Query<Object[]> query = pm.newQuery(JDOQuery.SQL_QUERY_LANGUAGE, Finding.QUERY_ALL_FINDINGS + queryFilter + " ORDER BY " + sortingAttributes.get(this.orderBy) + " " + (this.orderDirection.name().toLowerCase().equals("descending") ? " DESC" : "ASC"));
        PaginatedResult result = new PaginatedResult();
        query.setNamedParameters(params);
        final List<Object[]> totalList = query.executeList();
        result.setTotal(totalList.size());
        final List<Object[]> list = totalList.subList(this.pagination.getOffset(), (this.pagination.getOffset() + this.pagination.getLimit() >= totalList.size()) ? totalList.size() : this.pagination.getOffset() + this.pagination.getLimit());
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
        result.setObjects(findings);
        return result;
    }

    /**
     * Returns a List of all Finding objects filtered by ACL and other optional filters. The resulting list is grouped by vulnerability.
     * @param filters determines the filters to apply on the list of Finding objects
     * @param showInactive determines if inactive projects should be included or not
     * @return a List of Finding objects
     */
    public PaginatedResult getAllFindingsGroupedByVulnerability(final Map<String, String> filters, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        Map<String, Object> params = new HashMap<>();
        if (showInactive) {
            queryFilter.append(" WHERE (\"PROJECT\".\"ACTIVE\" = :active OR \"PROJECT\".\"ACTIVE\" IS NULL)");
            params.put("active", true);
        }
        processFilters(filters, queryFilter, params, true);
        final Query<Object[]> query = pm.newQuery(JDOQuery.SQL_QUERY_LANGUAGE, GroupedFinding.QUERY + queryFilter + " ORDER BY " + sortingAttributes.get(this.orderBy) + " " + (this.orderDirection.name().toLowerCase().equals("descending") ? " DESC" : "ASC"));
        PaginatedResult result = new PaginatedResult();
        query.setNamedParameters(params);
        final List<Object[]> totalList = query.executeList();
        result.setTotal(totalList.size());
        final List<Object[]> list = totalList.subList(this.pagination.getOffset(), (this.pagination.getOffset() + this.pagination.getLimit() >= totalList.size()) ? totalList.size() : this.pagination.getOffset() + this.pagination.getLimit());
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
            queryFilter.append("""
                    GROUP BY "VULNERABILITY"."ID",\s
                             "VULNERABILITY"."SOURCE",\s
                             "VULNERABILITY"."VULNID",\s
                             "VULNERABILITY"."TITLE",\s
                             "VULNERABILITY"."SEVERITY",
                             "VULNERABILITY"."CVSSV2BASESCORE",
                             "VULNERABILITY"."CVSSV3BASESCORE",
                             "VULNERABILITY"."OWASPRRLIKELIHOODSCORE",
                             "VULNERABILITY"."OWASPRRTECHNICALIMPACTSCORE",
                             "VULNERABILITY"."OWASPRRBUSINESSIMPACTSCORE",
                             "FINDINGATTRIBUTION"."ANALYZERIDENTITY",
                             "VULNERABILITY"."PUBLISHED",
                             "VULNERABILITY"."CWES"
                    """);
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
                if (filters[i].equals("NOT_SET") && (paramName.equals("analysisStatus") || paramName.equals("vendorResponse"))) {
                    queryFilter.append(" OR ").append(column).append(" IS NULL");
                }
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
            if (DbUtil.isPostgreSQL()) {
                queryFilter.append(column).append(fromValue ? " >= " : " <= ");
                if (isDate) {
                    queryFilter.append("TO_TIMESTAMP('").append(filter).append(fromValue ? " 00:00:00" : " 23:59:59").append("', 'YYYY-MM-DD HH24:MI:SS')");
                } else {
                    queryFilter.append("CAST('").append(filter).append("' AS NUMERIC)");
                }
            } else {
                queryFilter.append(column).append(fromValue ? " >= :" : " <= :").append(paramName);
                String value = filter;
                if (isDate) {
                    value += (fromValue ? " 00:00:00" : " 23:59:59");
                }
                params.put(paramName, value);
            }
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
            if (DbUtil.isPostgreSQL()) {
                queryFilter.append(column).append(fromValue ? " >= " : " <= ");
                queryFilter.append("TO_TIMESTAMP('").append(filter).append(fromValue ? " 00:00:00" : " 23:59:59").append("', 'YYYY-MM-DD HH24:MI:SS')");
            } else {
                queryFilter.append(column).append(fromValue ? " >= :" : " <= :").append(paramName);
                String value = filter;
                value += (fromValue ? " 00:00:00" : " 23:59:59");
                params.put(paramName, value);
            }
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
