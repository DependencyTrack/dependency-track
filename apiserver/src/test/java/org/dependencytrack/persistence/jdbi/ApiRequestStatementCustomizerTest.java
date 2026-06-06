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
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Team;
import alpine.model.User;
import alpine.persistence.OrderDirection;
import alpine.persistence.Pagination;
import alpine.resources.AlpineRequest;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.exception.InvalidSortFieldException;
import org.dependencytrack.persistence.jdbi.ApiRequestConfig.OrderingColumn;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.core.statement.StatementCustomizer;
import org.junit.jupiter.api.Test;

import java.sql.PreparedStatement;
import java.util.Collections;
import java.util.Set;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.model.ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

public class ApiRequestStatementCustomizerTest extends PersistenceCapableTest {

    // language=InjectedFreeMarker
    private static final String TEST_QUERY_TEMPLATE = """
            <#-- @ftlvariable name="apiFilterParameter" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT 1 AS "valueA"
                 , 2 AS "valueB"
              FROM "PROJECT"
             WHERE ${apiProjectAclCondition}
            <#if apiFilterParameter??>
               AND 'foo' = ${apiFilterParameter}
            </#if>
            ${apiOrderByClause!}
            ${apiOffsetLimitClause!}
            """;

    @Test
    public void testWithoutAlpineRequest() {
        useJdbiHandle(handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE
                            """);

                    assertThat(ctx.getBinding()).hasToString("{}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithAlpineRequestFilter() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ null,
                /* filter */ "foo",
                /* orderBy */ null,
                /* orderDirection */ null
        );

        useJdbiHandle(request, handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE AND 'foo' = :apiFilter
                            """);

                    assertThat(ctx.getBinding()).hasToString("{named:{apiFilter:foo}}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithAlpineRequestPagination() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ new Pagination(Pagination.Strategy.PAGES, 1, 100),
                /* filter */ null,
                /* orderBy */ null,
                /* orderDirection */ null
        );

        useJdbiHandle(request, handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE
                            OFFSET :paginationOffset FETCH NEXT :paginationLimit ROWS ONLY
                            """);

                    assertThat(ctx.getBinding()).hasToString("{named:{paginationOffset:0,paginationLimit:100}}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithAlpineRequestOrderingWithoutAllowedColumns() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ "value",
                /* orderDirection */ OrderDirection.DESCENDING
        );

        useJdbiHandle(request, handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE
                            """);

                    assertThat(ctx.getBinding()).hasToString("{}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithAlpineRequestOrderingEmptyAllowedColumns() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ "value",
                /* orderDirection */ OrderDirection.DESCENDING
        );

        assertThatExceptionOfType(InvalidSortFieldException.class)
                .isThrownBy(() -> useJdbiHandle(request, handle -> handle
                        .configure(ApiRequestConfig.class, config ->
                                config.setOrderingAllowedColumns(Collections.emptySet()))
                        .createQuery(TEST_QUERY_TEMPLATE)
                        .mapTo(Integer.class)
                        .findOne()))
                .withMessage("Sorting by field 'value' is not supported")
                .satisfies(e -> {
                    assertThat(e.getFieldName()).isEqualTo("value");
                    assertThat(e.getAllowedFieldNames()).isNull();
                });
    }

    @Test
    public void testWithAlpineRequestOrderingWithoutNotAllowedColumn() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ "foobar",
                /* orderDirection */ OrderDirection.DESCENDING
        );

        assertThatExceptionOfType(InvalidSortFieldException.class)
                .isThrownBy(() -> useJdbiHandle(request, handle -> handle
                        .configure(ApiRequestConfig.class, config ->
                                config.setOrderingAllowedColumns(Set.of(new OrderingColumn("valueA"))))
                        .createQuery(TEST_QUERY_TEMPLATE)
                        .mapTo(Integer.class)
                        .findOne()))
                .withMessage("Sorting by field 'foobar' is not supported")
                .satisfies(e -> {
                    assertThat(e.getFieldName()).isEqualTo("foobar");
                    assertThat(e.getAllowedFieldNames()).containsOnly("valueA");
                });
    }

    @Test
    public void testWithAlpineRequestOrderingWithAllowedColumns() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ "valueA",
                /* orderDirection */ OrderDirection.DESCENDING
        );

        useJdbiHandle(request, handle -> handle
                .configure(ApiRequestConfig.class, config ->
                        config.setOrderingAllowedColumns(Set.of(new OrderingColumn("valueA"))))
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE ORDER BY "valueA" DESC
                            """);

                    assertThat(ctx.getBinding()).hasToString("{}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithAlpineRequestOrderingWithAlwaysByNotAllowed() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ "valueA",
                /* orderDirection */ OrderDirection.DESCENDING
        );

        assertThatExceptionOfType(InvalidSortFieldException.class)
                .isThrownBy(() -> useJdbiHandle(request, handle -> handle
                        .configure(ApiRequestConfig.class, config -> {
                            config.setOrderingAllowedColumns(Set.of(new OrderingColumn("valueA")));
                            config.setOrderingAlwaysBy("foobar");
                        })
                        .createQuery(TEST_QUERY_TEMPLATE)
                        .mapTo(Integer.class)
                        .findOne()))
                .withMessage("Sorting by field 'foobar' is not supported")
                .satisfies(e -> {
                    assertThat(e.getFieldName()).isEqualTo("foobar");
                    assertThat(e.getAllowedFieldNames()).containsOnly("valueA");
                });
    }

    @Test
    public void testWithAlpineRequestOrderingWithAlwaysByInvalidFormat() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ "valueA",
                /* orderDirection */ OrderDirection.DESCENDING
        );

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> useJdbiHandle(request, handle -> handle
                        .configure(ApiRequestConfig.class, config -> {
                            config.setOrderingAllowedColumns(Set.of(new OrderingColumn("valueA")));
                            config.setOrderingAlwaysBy("foo bar baz");
                        })
                        .createQuery(TEST_QUERY_TEMPLATE)
                        .mapTo(Integer.class)
                        .findOne()))
                .withMessage("alwaysBy must consist of no more than two parts");
    }

    @Test
    public void testWithAlpineRequestOrderingWithAlwaysByMatchingOrderBy() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ "valueA",
                /* orderDirection */ OrderDirection.DESCENDING
        );

        useJdbiHandle(request, handle -> handle
                .configure(ApiRequestConfig.class, config -> {
                    config.setOrderingAllowedColumns(Set.of(new OrderingColumn("valueA")));
                    config.setOrderingAlwaysBy("valueA");
                })
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE ORDER BY "valueA" DESC
                            """);

                    assertThat(ctx.getBinding()).hasToString("{}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithAlpineRequestOrderingWithAlwaysBy() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ "valueA",
                /* orderDirection */ OrderDirection.DESCENDING
        );

        useJdbiHandle(request, handle -> handle
                .configure(ApiRequestConfig.class, config -> {
                    config.setOrderingAllowedColumns(Set.of(new OrderingColumn("valueA"), new OrderingColumn("valueB")));
                    config.setOrderingAlwaysBy("valueB");
                })
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE ORDER BY "valueA" DESC, "valueB"
                            """);

                    assertThat(ctx.getBinding()).hasToString("{}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithAlpineRequestOrderingWithAlwaysByAndDirection() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ "valueA",
                /* orderDirection */ OrderDirection.DESCENDING
        );

        useJdbiHandle(request, handle -> handle
                .configure(ApiRequestConfig.class, config -> {
                    config.setOrderingAllowedColumns(Set.of(new OrderingColumn("valueA"), new OrderingColumn("valueB")));
                    config.setOrderingAlwaysBy("valueB asc");
                })
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE ORDER BY "valueA" DESC, "valueB" asc
                            """);

                    assertThat(ctx.getBinding()).hasToString("{}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithAlpineRequestOrderingWithOnlyAlwaysBy() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ "valueB",
                /* orderDirection */ null
        );

        useJdbiHandle(request, handle -> handle
                .configure(ApiRequestConfig.class, config -> {
                    config.setOrderingAllowedColumns(Set.of(new OrderingColumn("valueB")));
                    config.setOrderingAlwaysBy("valueB");
                })
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE ORDER BY "valueB"
                            """);

                    assertThat(ctx.getBinding()).hasToString("{}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithPortfolioAclDisabled() {
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "false",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final ManagedUser managedUser = qm.createManagedUser("username", "passwordHash");

        final var request = new AlpineRequest(
                /* principal */ managedUser,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ null,
                /* orderDirection */ null
        );

        useJdbiHandle(request, handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE
                            """);

                    assertThat(ctx.getBinding()).hasToString("{}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithPortfolioAclEnabledWithNoTeams() {
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final ManagedUser managedUser = qm.createManagedUser("username", "passwordHash");

        final var request = new AlpineRequest(
                /* principal */ managedUser,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ null,
                /* orderDirection */ null
        );

        useJdbiHandle(request, handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace(/* language=SQL */ """
                            SELECT
                              1 AS "valueA",
                              2 AS "valueB"
                              FROM "PROJECT"
                             WHERE EXISTS(
                               SELECT 1
                                 FROM "PROJECT_ACCESS_USERS" AS pau
                                INNER JOIN "PROJECT_HIERARCHY" AS ph
                                   ON ph."PARENT_PROJECT_ID" = pau."PROJECT_ID"
                                WHERE ph."CHILD_PROJECT_ID" = "PROJECT"."ID"
                                  AND pau."USER_ID" = :projectAclUserId
                             )
                            """);

                    assertThat(ctx.getBinding())
                            .hasToString("{named:{projectAclUserId:%d}}".formatted(managedUser.getId()));
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithPortfolioAclEnabledWithApiKeyHavingPortfolioAccessControlBypassPermission() {
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final Team team = qm.createTeam("team");
        final ApiKey apiKey = qm.createApiKey(team);

        final var request = new AlpineRequest(
                /* principal */ apiKey,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ null,
                /* orderDirection */ null,
                /* effectivePermissions */ Set.of(Permissions.Constants.PORTFOLIO_ACCESS_CONTROL_BYPASS)
        );

        useJdbiHandle(request, handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE
                            """);

                    assertThat(ctx.getBinding()).hasToString("{}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithPortfolioAclEnabledWithManagedUserHavingPortfolioAccessControlBypassPermission() {
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final ManagedUser managedUser = qm.createManagedUser("username", "passwordHash");

        final var request = new AlpineRequest(
                /* principal */ managedUser,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ null,
                /* orderDirection */ null,
                /* effectivePermissions */ Set.of(Permissions.Constants.PORTFOLIO_ACCESS_CONTROL_BYPASS)
        );

        useJdbiHandle(request, handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE
                            """);

                    assertThat(ctx.getBinding()).hasToString("{}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithPortfolioAclEnabledWithLdapUserHavingPortfolioAccessControlBypassPermission() {
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final LdapUser ldapUser = qm.createLdapUser("username");

        final var request = new AlpineRequest(
                /* principal */ ldapUser,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ null,
                /* orderDirection */ null,
                /* effectivePermissions */ Set.of(Permissions.Constants.PORTFOLIO_ACCESS_CONTROL_BYPASS)
        );

        useJdbiHandle(request, handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE
                            """);

                    assertThat(ctx.getBinding()).hasToString("{}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithPortfolioAclEnabledWithOidcUserHavingPortfolioAccessControlBypassPermission() {
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final OidcUser oidcUser = qm.createOidcUser("username");

        final var request = new AlpineRequest(
                /* principal */ oidcUser,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ null,
                /* orderDirection */ null,
                /* effectivePermissions */ Set.of(Permissions.Constants.PORTFOLIO_ACCESS_CONTROL_BYPASS)
        );

        useJdbiHandle(request, handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA", 2 AS "valueB" FROM "PROJECT" WHERE TRUE
                            """);

                    assertThat(ctx.getBinding()).hasToString("{}");
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithPortfolioAclEnabledWithTeams() {
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final Team team = qm.createTeam("team");
        final ApiKey apiKey = qm.createApiKey(team);

        final var request = new AlpineRequest(
                /* principal */ apiKey,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ null,
                /* orderDirection */ null
        );

        useJdbiHandle(request, handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA"
                                 , 2 AS "valueB"
                              FROM "PROJECT"
                             WHERE EXISTS(
                               SELECT 1
                                 FROM "APIKEYS_TEAMS" AS akt
                                INNER JOIN "PROJECT_ACCESS_TEAMS" AS pat
                                   ON pat."TEAM_ID" = akt."TEAM_ID"
                                INNER JOIN "PROJECT_HIERARCHY" AS ph
                                   ON ph."PARENT_PROJECT_ID" = pat."PROJECT_ID"
                                WHERE akt."APIKEY_ID" = :projectAclApiKeyId
                                  AND ph."CHILD_PROJECT_ID" = "PROJECT"."ID"
                             )
                            """);

                    assertThat(ctx.getBinding()).hasToString("{named:{projectAclApiKeyId:%s}}".formatted(apiKey.getId()));
                }))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithPortfolioAclEnabledWithCustomizedAclStatement() {
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final Team team = qm.createTeam("team");
        final ApiKey apiKey = qm.createApiKey(team);

        final var request = new AlpineRequest(
                /* principal */ apiKey,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ null,
                /* orderDirection */ null
        );

        useJdbiHandle(request, handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA"
                                 , 2 AS "valueB"
                              FROM "PROJECT"
                             WHERE EXISTS(
                               SELECT 1
                                 FROM "APIKEYS_TEAMS" AS akt
                                INNER JOIN "PROJECT_ACCESS_TEAMS" AS pat
                                   ON pat."TEAM_ID" = akt."TEAM_ID"
                                INNER JOIN "PROJECT_HIERARCHY" AS ph
                                   ON ph."PARENT_PROJECT_ID" = pat."PROJECT_ID"
                                WHERE akt."APIKEY_ID" = :projectAclApiKeyId
                                  AND ph."CHILD_PROJECT_ID" = "PROJECT"."PARENT_PROJECT_ID"
                             )
                            """);

                    assertThat(ctx.getBinding()).hasToString("{named:{projectAclApiKeyId:%s}}".formatted(apiKey.getId()));
                }))
                .addCustomizer(new DefineApiProjectAclCondition.StatementCustomizer(
                        JdbiAttributes.ATTRIBUTE_API_PROJECT_ACL_CONDITION,
                        "\"PROJECT\".\"PARENT_PROJECT_ID\""))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    @Test
    public void testWithPortfolioAclEnabledWithUserPrincipalAndCustomizedAclStatement() {
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final User user = qm.createManagedUser("foo", "password");

        final var request = new AlpineRequest(
                /* principal */ user,
                /* pagination */ null,
                /* filter */ null,
                /* orderBy */ null,
                /* orderDirection */ null
        );

        useJdbiHandle(request, handle -> handle
                .addCustomizer(inspectStatement(ctx -> {
                    assertThat(ctx.getRenderedSql()).isEqualToIgnoringWhitespace("""
                            SELECT 1 AS "valueA"
                                 , 2 AS "valueB"
                              FROM "PROJECT"
                             WHERE EXISTS(
                               SELECT 1
                                FROM "PROJECT_ACCESS_USERS" AS pau
                               INNER JOIN "PROJECT_HIERARCHY" AS ph
                                  ON ph."PARENT_PROJECT_ID" = pau."PROJECT_ID"
                               WHERE ph."CHILD_PROJECT_ID" = "PROJECT"."PARENT_PROJECT_ID"
                                 AND pau."USER_ID" = :projectAclUserId
                             )
                            """);

                    assertThat(ctx.getBinding()).hasToString("{named:{projectAclUserId:%s}}".formatted(user.getId()));
                }))
                .addCustomizer(new DefineApiProjectAclCondition.StatementCustomizer(
                        JdbiAttributes.ATTRIBUTE_API_PROJECT_ACL_CONDITION,
                        "\"PROJECT\".\"PARENT_PROJECT_ID\""))
                .createQuery(TEST_QUERY_TEMPLATE)
                .mapTo(Integer.class)
                .findOne());
    }

    private static StatementInspector inspectStatement(final Consumer<StatementContext> contextConsumer) {
        return new StatementInspector(contextConsumer);
    }

    private record StatementInspector(Consumer<StatementContext> contextConsumer) implements StatementCustomizer {

        @Override
        public void beforeExecution(final PreparedStatement stmt, final StatementContext ctx) {
            contextConsumer.accept(ctx);
        }

    }

}