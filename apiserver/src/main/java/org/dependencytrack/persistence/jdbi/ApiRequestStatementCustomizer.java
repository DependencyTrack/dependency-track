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
package org.dependencytrack.persistence.jdbi;

import alpine.model.ApiKey;
import alpine.model.User;
import alpine.persistence.OrderDirection;
import alpine.resources.AlpineRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.auth.ProjectAccess;
import org.dependencytrack.exception.InvalidSortFieldException;
import org.dependencytrack.persistence.Ordering;
import org.dependencytrack.persistence.jdbi.ApiRequestConfig.AlwaysByOrdering;
import org.dependencytrack.persistence.jdbi.ApiRequestConfig.OrderingColumn;
import org.jdbi.v3.core.qualifier.QualifiedType;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.core.statement.StatementCustomizer;

import javax.jdo.Query;
import java.security.Principal;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Map;

import static org.dependencytrack.model.ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_API_FILTER_PARAMETER;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_API_OFFSET_LIMIT_CLAUSE;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_API_ORDER_BY_CLAUSE;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_API_PROJECT_ACL_CONDITION;

/**
 * A {@link StatementCustomizer} that enriches the {@link StatementContext}
 * with attributes and parameter bindings for:
 * <ul>
 *     <li>filtering: {@value JdbiAttributes#ATTRIBUTE_API_FILTER_PARAMETER}</li>
 *     <li>pagination: {@value JdbiAttributes#ATTRIBUTE_API_OFFSET_LIMIT_CLAUSE}</li>
 *     <li>ordering: {@value JdbiAttributes#ATTRIBUTE_API_ORDER_BY_CLAUSE}</li>
 *     <li>portfolio access control: {@value JdbiAttributes#ATTRIBUTE_API_PROJECT_ACL_CONDITION}</li>
 * </ul>
 * based on a provided {@link AlpineRequest}.
 * <p>
 * The functionality provided by this customizer is equivalent to these JDO counterparts:
 * <ul>
 *     <li>{@link org.dependencytrack.persistence.QueryManager#decorate(Query)}</li>
 *     <li>{@link org.dependencytrack.persistence.ProjectQueryManager#preprocessACLs(Query, String, Map)}</li>
 * </ul>
 *
 * @since 5.0.0
 */
class ApiRequestStatementCustomizer implements StatementCustomizer {

    static final String PARAMETER_PROJECT_ACL_API_KEY_ID = "projectAclApiKeyId";
    static final String PARAMETER_PROJECT_ACL_USER_ID = "projectAclUserId";
    static final String TEMPLATE_API_KEY_PROJECT_ACL_CONDITION = /* language=SQL */ """
            EXISTS(
              SELECT 1
                FROM "APIKEYS_TEAMS" AS akt
               INNER JOIN "PROJECT_ACCESS_TEAMS" AS pat
                  ON pat."TEAM_ID" = akt."TEAM_ID"
               INNER JOIN "PROJECT_HIERARCHY" AS ph
                  ON ph."PARENT_PROJECT_ID" = pat."PROJECT_ID"
               WHERE akt."APIKEY_ID" = :projectAclApiKeyId
                 AND ph."CHILD_PROJECT_ID" = %s
            )
            """;
    static final String TEMPLATE_USER_PROJECT_ACL_CONDITION = /* language=SQL */ """
            EXISTS(
              SELECT 1
                FROM "PROJECT_ACCESS_USERS" AS pau
               INNER JOIN "PROJECT_HIERARCHY" AS ph
                  ON ph."PARENT_PROJECT_ID" = pau."PROJECT_ID"
               WHERE ph."CHILD_PROJECT_ID" = %s
                 AND pau."USER_ID" = :projectAclUserId
            )
            """;

    private final AlpineRequest apiRequest;

    ApiRequestStatementCustomizer(final AlpineRequest apiRequest) {
        this.apiRequest = apiRequest;
    }

    @Override
    public void beforeTemplating(final PreparedStatement stmt, final StatementContext ctx) throws SQLException {
        defineFilter(ctx);
        defineOrdering(ctx);
        definePagination(ctx);
        defineProjectAclCondition(ctx);
    }

    private void defineFilter(final StatementContext ctx) {
        if (apiRequest == null || apiRequest.getFilter() == null) {
            return;
        }

        ctx.define(ATTRIBUTE_API_FILTER_PARAMETER, ":apiFilter");
        ctx.getBinding().addNamed("apiFilter", apiRequest.getFilter());
    }

    private void defineOrdering(final StatementContext ctx) {
        if (apiRequest == null) {
            return;
        }

        final var ordering = new Ordering(apiRequest);
        final var orderingBuilder = new StringBuilder();
        final var config = ctx.getConfig(ApiRequestConfig.class);

        if (apiRequest.getOrderBy() != null) {
            if (config.orderingAllowedColumns() == null) {
                return;
            }
            if (config.orderingAllowedColumns().isEmpty()) {
                throw new InvalidSortFieldException(apiRequest.getOrderBy());
            }
            final OrderingColumn orderingColumn = config
                    .orderingAllowedColumn(ordering.by())
                    .orElseThrow(() -> new InvalidSortFieldException(
                            ordering.by(),
                            config.orderingAllowedColumns().stream()
                                    .map(OrderingColumn::name)
                                    .toList()));

            final String orderByColumnSql =
                    orderingColumn.queryName() != null
                            ? orderingColumn.queryName()
                            : "\"" + ordering.by() + "\"";

            orderingBuilder.append("ORDER BY ").append(orderByColumnSql);

            if (ordering.direction() != null && ordering.direction() != OrderDirection.UNSPECIFIED) {
                orderingBuilder
                        .append(" ")
                        .append(ordering.direction() == OrderDirection.ASCENDING ? "ASC" : "DESC");
            }

            final AlwaysByOrdering alwaysBy = config.orderingAlwaysBy();
            if (alwaysBy != null && !alwaysBy.queryName().equals(orderByColumnSql)) {
                orderingBuilder.append(", ").append(alwaysBy.queryName());
                if (alwaysBy.direction() != null && alwaysBy.direction() != OrderDirection.UNSPECIFIED) {
                    orderingBuilder
                            .append(" ")
                            .append(alwaysBy.direction() == OrderDirection.ASCENDING ? "ASC" : "DESC");
                }
            }
        }

        if (!orderingBuilder.isEmpty()) {
            ctx.define(ATTRIBUTE_API_ORDER_BY_CLAUSE, orderingBuilder.toString());
        }
    }

    private void definePagination(final StatementContext ctx) {
        if (apiRequest != null
                && apiRequest.getPagination() != null
                && apiRequest.getPagination().isPaginated()) {
            ctx.define(ATTRIBUTE_API_OFFSET_LIMIT_CLAUSE, "OFFSET :paginationOffset FETCH NEXT :paginationLimit ROWS ONLY");
            ctx.getBinding().addNamed("paginationOffset", apiRequest.getPagination().getOffset());
            ctx.getBinding().addNamed("paginationLimit", apiRequest.getPagination().getLimit());
        }
    }

    private void defineProjectAclCondition(final StatementContext ctx) throws SQLException {
        if (apiRequest == null
                || apiRequest.getPrincipal() == null
                || ProjectAccess.isUnrestricted()
                || !isAclEnabled(ctx)
                || apiRequest.getEffectivePermissions().contains(Permissions.Constants.PORTFOLIO_ACCESS_CONTROL_BYPASS)) {
            ctx.define(ATTRIBUTE_API_PROJECT_ACL_CONDITION, "TRUE");
            return;
        }

        final Principal principal = apiRequest.getPrincipal();
        final ApiRequestConfig config = ctx.getConfig(ApiRequestConfig.class);

        switch (principal) {
            case User user -> {
                ctx.define(ATTRIBUTE_API_PROJECT_ACL_CONDITION,
                        TEMPLATE_USER_PROJECT_ACL_CONDITION.formatted(config.projectAclProjectIdColumn()));
                ctx.getBinding().addNamed(PARAMETER_PROJECT_ACL_USER_ID, user.getId(), QualifiedType.of(Long.class));
            }
            case ApiKey apiKey -> {
                ctx.define(ATTRIBUTE_API_PROJECT_ACL_CONDITION,
                        TEMPLATE_API_KEY_PROJECT_ACL_CONDITION.formatted(config.projectAclProjectIdColumn()));
                ctx.getBinding().addNamed(PARAMETER_PROJECT_ACL_API_KEY_ID, apiKey.getId(), QualifiedType.of(Long.class));
            }
            default -> {
                ctx.define(ATTRIBUTE_API_PROJECT_ACL_CONDITION, "FALSE");
            }
        }
    }

    private boolean isAclEnabled(final StatementContext ctx) throws SQLException {
        try (final PreparedStatement ps = ctx.getConnection().prepareStatement("""
                SELECT 1
                  FROM "CONFIGPROPERTY"
                 WHERE "GROUPNAME" = ?
                   AND "PROPERTYNAME" = ?
                   AND "PROPERTYVALUE" = 'true'
                """)) {
            ps.setString(1, ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName());
            ps.setString(2, ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName());
            return ps.executeQuery().next();
        }
    }

}
