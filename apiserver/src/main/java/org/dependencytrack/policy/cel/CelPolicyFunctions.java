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
package org.dependencytrack.policy.cel;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import jakarta.annotation.Nullable;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.parser.spdx.expression.SpdxExpressions;
import org.dependencytrack.policy.cel.persistence.CelPolicyDao;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.VersionDistance;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.substringAfter;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_QUERY_NAME;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.COMPARE_AGE;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.DEPENDS_ON;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.IS_DEPENDENCY_OF;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.IS_DIRECT_DEPENDENCY_OF;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.IS_EXCLUSIVE_DEPENDENCY_OF;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.MATCHES_RANGE;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.VERSION_DISTANCE;

final class CelPolicyFunctions {

    private static final Logger LOGGER = LoggerFactory.getLogger(CelPolicyFunctions.class);

    private CelPolicyFunctions() {
    }

    static boolean dependsOn(final Project project, final Component component) {
        if (project.getUuid().isBlank()) {
            LOGGER.warn("%s: project does not have a UUID; Unable to evaluate, returning false".formatted(DEPENDS_ON.functionName()));
            return false;
        }

        final var compositeNodeFilter = CompositeDependencyNodeFilter.of(component);
        if (!compositeNodeFilter.hasSqlFilters()) {
            LOGGER.warn("""
                    %s: Unable to construct filter expression from component %s; \
                    Unable to evaluate, returning false""".formatted(DEPENDS_ON.functionName(), component));
            return false;
        }

        try (final Handle jdbiHandle = openJdbiHandle()) {
            if (!compositeNodeFilter.hasInMemoryFilters()) {
                final Query query = jdbiHandle.createQuery("""
                        WITH "CTE_PROJECT" AS (
                          SELECT "ID"
                            FROM "PROJECT"
                           WHERE "UUID" = :projectUuid
                        )
                        SELECT COUNT(*)
                          FROM "COMPONENT"
                         WHERE "PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                           AND ${filters}
                        """);
                return query
                        .define(ATTRIBUTE_QUERY_NAME, "%s#dependsOn_withoutInMemoryFilters".formatted(CelPolicyFunctions.class.getSimpleName()))
                        .define("filters", compositeNodeFilter.sqlFiltersConjunctive())
                        .bind("projectUuid", UUID.fromString(project.getUuid()))
                        .bindMap(compositeNodeFilter.sqlFilterParams())
                        .mapTo(Long.class)
                        .map(count -> count > 0)
                        .one();
            }

            final Query query = jdbiHandle.createQuery("""
                    WITH "CTE_PROJECT" AS (
                      SELECT "ID"
                        FROM "PROJECT"
                       WHERE "UUID" = :projectUuid
                    )
                    SELECT ${selectColumnNames?join(", ")}
                      FROM "COMPONENT"
                     WHERE "PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                       AND ${filters}
                    """);
            return query
                    .define(ATTRIBUTE_QUERY_NAME, "%s#dependsOn_withInMemoryFilters".formatted(CelPolicyFunctions.class.getSimpleName()))
                    .define("filters", compositeNodeFilter.sqlFiltersConjunctive())
                    .define("selectColumnNames", compositeNodeFilter.sqlSelectColumns())
                    .bind("projectUuid", UUID.fromString(project.getUuid()))
                    .bindMap(compositeNodeFilter.sqlFilterParams())
                    .map(ConstructorMapper.of(DependencyNode.class))
                    .stream()
                    .anyMatch(compositeNodeFilter.inMemoryFiltersConjunctive());
        }
    }

    static boolean isDependencyOf(final Component leafComponent, final Component rootComponent) {
        if (leafComponent.getUuid().isBlank()) {
            LOGGER.warn("%s: leaf component does not have a UUID; Unable to evaluate, returning false".formatted(IS_DEPENDENCY_OF.functionName()));
            return false;
        }

        final var compositeNodeFilter = CompositeDependencyNodeFilter.of(rootComponent);
        if (!compositeNodeFilter.hasSqlFilters()) {
            LOGGER.warn("""
                    %s: Unable to construct filter expression from root component %s; \
                    Unable to evaluate, returning false""".formatted(IS_DEPENDENCY_OF.functionName(), rootComponent));
            return false;
        }

        try (final Handle jdbiHandle = openJdbiHandle()) {
            if (!compositeNodeFilter.hasInMemoryFilters()) {
                final Query query = jdbiHandle.createQuery("""
                        WITH RECURSIVE "CTE_PROJECT" AS (
                          SELECT "PROJECT_ID" AS "ID"
                            FROM "COMPONENT"
                           WHERE "UUID" = :leafComponentUuid
                        ),
                        "CTE_MATCHES" AS (
                          SELECT "ID"
                            FROM "COMPONENT"
                           WHERE "PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                             AND "DIRECT_DEPENDENCIES" IS NOT NULL
                             AND ${filters}
                        ),
                        "CTE_DEPENDENCIES" ("UUID", "PROJECT_ID", "FOUND", "PATH") AS (
                          SELECT "C"."UUID"                                       AS "UUID"
                               , "C"."PROJECT_ID"                                 AS "PROJECT_ID"
                               , ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES")) AS "FOUND"
                               , ARRAY["C"."ID"]::BIGINT[]                        AS "PATH"
                            FROM "COMPONENT" AS "C"
                           WHERE EXISTS(SELECT 1 FROM "CTE_MATCHES")
                             AND "C"."PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                             AND "C"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', :leafComponentUuid))
                          UNION ALL
                          SELECT "C"."UUID"                                       AS "UUID"
                               , "C"."PROJECT_ID"                                 AS "PROJECT_ID"
                               , ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES")) AS "FOUND"
                               , ARRAY_APPEND("PREVIOUS"."PATH", "C"."ID")        AS "PATH"
                            FROM "COMPONENT" AS "C"
                           INNER JOIN "CTE_DEPENDENCIES" AS "PREVIOUS"
                              ON "PREVIOUS"."PROJECT_ID" = "C"."PROJECT_ID"
                           WHERE NOT "PREVIOUS"."FOUND"
                             AND NOT ("C"."ID" = ANY("PREVIOUS"."PATH"))
                             AND "C"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', "PREVIOUS"."UUID"))
                        )
                        SELECT BOOL_OR("FOUND")
                          FROM "CTE_DEPENDENCIES"
                        """);

                return query
                        .define(ATTRIBUTE_QUERY_NAME, "%s#isDependencyOf_withoutInMemoryFilters".formatted(CelPolicyFunctions.class.getSimpleName()))
                        .define("filters", compositeNodeFilter.sqlFiltersConjunctive())
                        .bind("leafComponentUuid", UUID.fromString(leafComponent.getUuid()))
                        .bindMap(compositeNodeFilter.sqlFilterParams())
                        .mapTo(Boolean.class)
                        .findOne()
                        .orElse(false);
            }

            final Query query = jdbiHandle.createQuery("""
                    WITH RECURSIVE "CTE_PROJECT" AS (
                      SELECT "PROJECT_ID" AS "ID"
                        FROM "COMPONENT"
                       WHERE "UUID" = :leafComponentUuid
                    ),
                    "CTE_MATCHES" AS (
                      SELECT "ID"
                        FROM "COMPONENT"
                       WHERE "PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                         AND "DIRECT_DEPENDENCIES" IS NOT NULL
                         AND ${filters}
                    ),
                    "CTE_DEPENDENCIES" ("UUID", "PROJECT_ID", ${selectColumnNames?join(", ", "", ", ")} "FOUND", "PATH") AS (
                      SELECT "C"."UUID" AS "UUID"
                           , "C"."PROJECT_ID" AS "PROJECT_ID"
                           <#list selectColumnNames as columnName>
                           , CASE
                               WHEN ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES"))
                               THEN "C".${columnName}
                             END AS ${columnName}
                           </#list>
                           , ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES")) AS "FOUND"
                           , ARRAY["C"."ID"]::BIGINT[] AS "PATH"
                        FROM "COMPONENT" AS "C"
                       WHERE EXISTS(SELECT 1 FROM "CTE_MATCHES")
                         AND "C"."PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                         AND "C"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', :leafComponentUuid))
                      UNION ALL
                      SELECT "C"."UUID" AS "UUID"
                           , "C"."PROJECT_ID" AS "PROJECT_ID"
                           <#list selectColumnNames as columnName>
                           , CASE
                               WHEN ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES"))
                               THEN "C".${columnName}
                             END AS ${columnName}
                           </#list>
                           , ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES")) AS "FOUND"
                           , ARRAY_APPEND("PREVIOUS"."PATH", "C"."ID") AS "PATH"
                        FROM "COMPONENT" AS "C"
                       INNER JOIN "CTE_DEPENDENCIES" AS "PREVIOUS"
                          ON "PREVIOUS"."PROJECT_ID" = "C"."PROJECT_ID"
                       WHERE NOT ("C"."ID" = ANY("PREVIOUS"."PATH"))
                         AND "C"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', "PREVIOUS"."UUID"))
                    )
                    SELECT ${selectColumnNames?join(", ")}
                      FROM "CTE_DEPENDENCIES"
                     WHERE "FOUND"
                    """);

            return query
                    .define(ATTRIBUTE_QUERY_NAME, "%s#isDependencyOf_withInMemoryFilters".formatted(CelPolicyFunctions.class.getSimpleName()))
                    .define("filters", compositeNodeFilter.sqlFiltersConjunctive())
                    .define("selectColumnNames", compositeNodeFilter.sqlSelectColumns())
                    .bind("leafComponentUuid", UUID.fromString(leafComponent.getUuid()))
                    .bindMap(compositeNodeFilter.sqlFilterParams())
                    .map(ConstructorMapper.of(DependencyNode.class))
                    .stream()
                    .anyMatch(compositeNodeFilter.inMemoryFiltersConjunctive());
        }
    }

    static boolean isExclusiveDependencyOf(final Component leafComponent, final Component rootComponent) {
        if (leafComponent.getUuid().isBlank()) {
            LOGGER.warn("%s: leaf component does not have a UUID; Unable to evaluate, returning false".formatted(IS_EXCLUSIVE_DEPENDENCY_OF.functionName()));
            return false;
        }

        final var compositeNodeFilter = CompositeDependencyNodeFilter.of(rootComponent);
        if (!compositeNodeFilter.hasSqlFilters()) {
            LOGGER.warn("""
                    %s: Unable to construct filter expression from root component %s; \
                    Unable to evaluate, returning false""".formatted(IS_EXCLUSIVE_DEPENDENCY_OF.functionName(), rootComponent));
            return false;
        }

        try (final Handle jdbiHandle = openJdbiHandle()) {
            if (new CelPolicyDao(jdbiHandle).isDirectDependency(leafComponent)) {
                return false;
            }

            final Query query = jdbiHandle.createQuery("""
                    WITH RECURSIVE "CTE_PROJECT" AS (
                      SELECT "PROJECT_ID" AS "ID"
                        FROM "COMPONENT"
                       WHERE "UUID" = :leafComponentUuid
                    ),
                    "CTE_MATCHES" AS (
                      SELECT "ID"
                        FROM "COMPONENT"
                       WHERE "PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                         AND "DIRECT_DEPENDENCIES" IS NOT NULL
                         AND ${filters}
                    ),
                    "CTE_DEPENDENCIES" ("ID", "UUID", "PROJECT_ID", ${selectColumnNames?join(", ", "", ", ")} "FOUND", "PATH") AS (
                      SELECT "C"."ID" AS "ID"
                           , "C"."UUID" AS "UUID"
                           , "C"."PROJECT_ID" AS "PROJECT_ID"
                           <#list selectColumnNames as columnName>
                           , CASE
                               WHEN ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES"))
                               THEN "C".${columnName}
                             END AS ${columnName}
                           </#list>
                           , ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES")) AS "FOUND"
                           , ARRAY["C"."ID"]::BIGINT[] AS "PATH"
                        FROM "COMPONENT" AS "C"
                       WHERE EXISTS(SELECT 1 FROM "CTE_MATCHES")
                         AND "C"."PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                         AND "C"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', :leafComponentUuid))
                      UNION ALL
                      SELECT "C"."ID" AS "ID"
                           , "C"."UUID" AS "UUID"
                           , "C"."PROJECT_ID" AS "PROJECT_ID"
                           <#list selectColumnNames as columnName>
                           , CASE
                               WHEN ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES"))
                               THEN "C".${columnName}
                             END AS ${columnName}
                           </#list>
                           , ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES")) AS "FOUND"
                           , ARRAY_APPEND("PREVIOUS"."PATH", "C"."ID") AS "PATH"
                        FROM "COMPONENT" AS "C"
                       INNER JOIN "CTE_DEPENDENCIES" AS "PREVIOUS"
                          ON "PREVIOUS"."PROJECT_ID" = "C"."PROJECT_ID"
                       WHERE NOT ("C"."ID" = ANY("PREVIOUS"."PATH"))
                         AND "C"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', "PREVIOUS"."UUID"))
                    )
                    SELECT "ID"
                         , ${selectColumnNames?join(", ", "", ", ")} "FOUND"
                         , "PATH"
                      FROM "CTE_DEPENDENCIES"
                    """);

            final List<DependencyNode> nodes = query
                    .define(ATTRIBUTE_QUERY_NAME, "%s#isExclusiveDependencyOf".formatted(CelPolicyFunctions.class.getSimpleName()))
                    .define("filters", compositeNodeFilter.sqlFiltersConjunctive())
                    .define("selectColumnNames", compositeNodeFilter.sqlSelectColumns())
                    .bind("leafComponentUuid", UUID.fromString(leafComponent.getUuid()))
                    .bindMap(compositeNodeFilter.sqlFilterParams())
                    .map(ConstructorMapper.of(DependencyNode.class))
                    .list();
            if (nodes.isEmpty()) {
                return false;
            }

            final Set<Long> matchedNodeIds = nodes.stream()
                    .filter(node -> node.found() != null && node.found())
                    .filter(compositeNodeFilter.inMemoryFiltersConjunctive())
                    .map(DependencyNode::id)
                    .collect(Collectors.toSet());
            if (matchedNodeIds.isEmpty()) {
                return false;
            }

            final List<List<Long>> paths = reducePaths(nodes);

            return paths.stream().allMatch(path -> path.stream().anyMatch(matchedNodeIds::contains));
        }
    }

    static boolean isDirectDependencyOf(final Component childComponent,
                                        final Component parentTemplate) {
        if (childComponent.getUuid().isBlank()) {
            LOGGER.warn("%s: leaf component does not have a UUID; returning false".formatted(IS_DIRECT_DEPENDENCY_OF.functionName()));
            return false;
        }

        final var compositeNodeFilter = CompositeDependencyNodeFilter.of(parentTemplate);
        if (!compositeNodeFilter.hasSqlFilters()) {
            LOGGER.warn("""
                    %s: Unable to construct filter expression from parent component %s; \
                    returning false""".formatted(IS_DIRECT_DEPENDENCY_OF.functionName(), parentTemplate));
            return false;
        }

        try (final Handle jdbiHandle = openJdbiHandle()) {
            if (!compositeNodeFilter.hasInMemoryFilters()) {
                final Query query = jdbiHandle.createQuery("""
                        WITH "CTE_PROJECT" AS (
                          SELECT "PROJECT_ID" AS "ID"
                            FROM "COMPONENT"
                           WHERE "UUID" = :childUuid
                        )
                        SELECT EXISTS(
                          SELECT 1
                            FROM "COMPONENT" AS "PARENT"
                           WHERE "PARENT"."PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                             AND "PARENT"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(
                                   JSONB_BUILD_OBJECT('uuid', :childUuid))
                             AND ${filters}
                        )
                        """);
                return query
                        .define(ATTRIBUTE_QUERY_NAME,
                                "%s#isDirectDependencyOf_withoutInMemoryFilters".formatted(CelPolicyFunctions.class.getSimpleName()))
                        .define("filters", compositeNodeFilter.sqlFiltersConjunctive())
                        .bind("childUuid", UUID.fromString(childComponent.getUuid()))
                        .bindMap(compositeNodeFilter.sqlFilterParams())
                        .mapTo(Boolean.class)
                        .one();
            }

            final Query query = jdbiHandle.createQuery("""
                    WITH "CTE_PROJECT" AS (
                      SELECT "PROJECT_ID" AS "ID"
                        FROM "COMPONENT"
                       WHERE "UUID" = :childUuid
                    ),
                    "CTE_PARENTS" ("ID", "UUID", "PROJECT_ID"
                         , ${selectColumnNames?join(", ", "", ", ")} "FOUND", "PATH") AS (
                      SELECT "PARENT"."ID" AS "ID"
                           , "PARENT"."UUID" AS "UUID"
                           , "PARENT"."PROJECT_ID" AS "PROJECT_ID"
                           <#list selectColumnNames as columnName>
                           , "PARENT".${columnName} AS ${columnName}
                           </#list>
                           , TRUE AS "FOUND"
                           , ARRAY["PARENT"."ID"]::BIGINT[] AS "PATH"
                        FROM "COMPONENT" AS "PARENT"
                       WHERE "PARENT"."PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                         AND "PARENT"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(
                               JSONB_BUILD_OBJECT('uuid', :childUuid))
                         AND ${filters}
                    )
                    SELECT "ID"
                         , "UUID"
                         , "PROJECT_ID"
                         , ${selectColumnNames?join(", ", "", ", ")} "FOUND"
                         , "PATH"
                      FROM "CTE_PARENTS"
                    """);

            return query
                    .define(ATTRIBUTE_QUERY_NAME,
                            "%s#isDirectDependencyOf_withInMemoryFilters".formatted(CelPolicyFunctions.class.getSimpleName()))
                    .define("filters", compositeNodeFilter.sqlFiltersConjunctive())
                    .define("selectColumnNames", compositeNodeFilter.sqlSelectColumns())
                    .bind("childUuid", UUID.fromString(childComponent.getUuid()))
                    .bindMap(compositeNodeFilter.sqlFilterParams())
                    .map(ConstructorMapper.of(DependencyNode.class))
                    .stream()
                    .anyMatch(compositeNodeFilter.inMemoryFiltersConjunctive());
        }
    }

    static boolean matchesRange(final String version, final String versStr) {
        try {
            return Vers.parse(versStr).contains(version);
        } catch (VersException e) {
            LOGGER.warn("%s: Failed to check if version %s matches range %s"
                    .formatted(MATCHES_RANGE.functionName(), version, versStr), e);
            return false;
        }
    }

    static boolean matchesVersionDistance(Component component, String comparator, VersionDistance value) {
        try {
            if (!component.hasPurl()) {
                LOGGER.warn("%s: Component does not have a purl; returning false".formatted(VERSION_DISTANCE.functionName()));
                return false;
            }
            try {
                if (RepositoryType.resolve(new PackageURL(component.getPurl())) == RepositoryType.UNSUPPORTED) {
                    LOGGER.warn("%s: Unsupported repository type for component; returning false".formatted(VERSION_DISTANCE.functionName()));
                    return false;
                }
            } catch (MalformedPackageURLException ex) {
                LOGGER.warn("%s: Invalid package url %s; returning false".formatted(VERSION_DISTANCE.functionName(), component.getPurl()));
                return false;
            }
            if (!component.hasLatestVersion()) {
                LOGGER.warn("%s: Component does not have latest version information; returning false".formatted(VERSION_DISTANCE.functionName()));
                return false;
            }
            return evaluateVersionDistance(component, comparator, value);
        } catch (Exception ex) {
            LOGGER.warn("""
                    %s: Was unable to parse dynamic message for version distance policy; \
                    Unable to resolve, returning false""".formatted(VERSION_DISTANCE.functionName()));
            return false;
        }
    }

    private static boolean evaluateVersionDistance(Component component, String comparator, VersionDistance value) {
        String comparatorComputed = switch (comparator) {
            case "NUMERIC_GREATER_THAN", ">" -> "NUMERIC_GREATER_THAN";
            case "NUMERIC_GREATER_THAN_OR_EQUAL", ">=" -> "NUMERIC_GREATER_THAN_OR_EQUAL";
            case "NUMERIC_EQUAL", "==" -> "NUMERIC_EQUAL";
            case "NUMERIC_NOT_EQUAL", "!=" -> "NUMERIC_NOT_EQUAL";
            case "NUMERIC_LESSER_THAN_OR_EQUAL", "<=" -> "NUMERIC_LESSER_THAN_OR_EQUAL";
            case "NUMERIC_LESS_THAN", "<" -> "NUMERIC_LESS_THAN";
            default -> "";
        };
        if (comparatorComputed.isEmpty()) {
            LOGGER.warn("""
                    %s: Unsupported operator %s for version distance policy; \
                    Unable to resolve, returning false""".formatted(VERSION_DISTANCE.functionName(), comparator));
            return false;
        }
        final org.dependencytrack.model.VersionDistance versionDistance;
        try {
            versionDistance = org.dependencytrack.model.VersionDistance.getVersionDistance(
                    component.getVersion(), component.getLatestVersion());
        } catch (RuntimeException e) {
            LOGGER.warn("""
                    %s: Failed to compute version distance for component %s (UUID: %s), \
                    between component version %s and latest version %s; Skipping\
                    """.formatted(VERSION_DISTANCE.functionName(), component, component.getUuid(), component.getVersion(), component.getLatestVersion()), e);
            return false;
        }
        final boolean isDirectDependency = withJdbiHandle(
                handle -> new CelPolicyDao(handle).isDirectDependency(component));
        return isDirectDependency && org.dependencytrack.model.VersionDistance.evaluate(value, comparatorComputed, versionDistance);
    }

    static boolean isComponentOld(Component component, String comparator, String age) {
        if (!component.hasPurl()) {
            return false;
        }
        try {
            if (RepositoryType.resolve(new PackageURL(component.getPurl())) == RepositoryType.UNSUPPORTED) {
                return false;
            }
        } catch (MalformedPackageURLException ex) {
            return false;
        }
        if (!component.hasPublishedAt()) {
            return false;
        }
        var componentPublishedDate = component.getPublishedAt();
        final Period agePeriod;
        try {
            agePeriod = Period.parse(age);
        } catch (DateTimeParseException e) {
            LOGGER.error("%s: Invalid age duration format \"%s\"".formatted(COMPARE_AGE.functionName(), age), e);
            return false;
        }
        if (agePeriod.isZero() || agePeriod.isNegative()) {
            LOGGER.warn("%s: Age durations must not be zero or negative, but was %s".formatted(COMPARE_AGE.functionName(), agePeriod));
            return false;
        }
        Instant instant = Instant.ofEpochSecond(componentPublishedDate.getSeconds(), componentPublishedDate.getNanos());
        final LocalDate publishedDate = LocalDate.ofInstant(instant, ZoneId.systemDefault());
        final LocalDate ageDate = publishedDate.plus(agePeriod);
        final LocalDate today = LocalDate.now(ZoneId.systemDefault());
        return switch (comparator) {
            case "NUMERIC_GREATER_THAN", ">" -> ageDate.isBefore(today);
            case "NUMERIC_GREATER_THAN_OR_EQUAL", ">=" -> ageDate.isEqual(today) || ageDate.isBefore(today);
            case "NUMERIC_EQUAL", "==" -> ageDate.isEqual(today);
            case "NUMERIC_NOT_EQUAL", "!=" -> !ageDate.isEqual(today);
            case "NUMERIC_LESSER_THAN_OR_EQUAL", "<=" -> ageDate.isEqual(today) || ageDate.isAfter(today);
            case "NUMERIC_LESS_THAN", "<" -> ageDate.isAfter(LocalDate.now(ZoneId.systemDefault()));
            default -> {
                LOGGER.warn("%s: Operator %s is not supported for component age conditions".formatted(COMPARE_AGE.functionName(), comparator));
                yield false;
            }
        };
    }

    static boolean hasPackageArtifactHashMismatch(Component component) {
        return hashesDiffer(component.getMd5(), component.getPackageArtifactMd5())
                || hashesDiffer(component.getSha1(), component.getPackageArtifactSha1())
                || hashesDiffer(component.getSha256(), component.getPackageArtifactSha256())
                || hashesDiffer(component.getSha512(), component.getPackageArtifactSha512());
    }

    private static boolean hashesDiffer(String componentHash, String pkgArtifactHash) {
        return !componentHash.isEmpty()
                && !pkgArtifactHash.isEmpty()
                && !componentHash.equalsIgnoreCase(pkgArtifactHash);
    }

    @SuppressWarnings("unchecked")
    static boolean spdxExprAllows(String expr, List<?> ids) {
        return SpdxExpressions.allows(expr, (List<String>) ids);
    }

    @SuppressWarnings("unchecked")
    static boolean spdxExprRequiresAny(String expr, List<?> ids) {
        return SpdxExpressions.requiresAny(expr, (List<String>) ids);
    }

    /**
     * Reduce paths of all {@link DependencyNode}s to complete, unique paths.
     * e.g. [[3, 2, 1], [2, 1], [1]] reduces to [[3, 2, 1]].
     */
    static List<List<Long>> reducePaths(final List<DependencyNode> nodes) {
        return nodes.stream()
                .map(DependencyNode::path)
                .sorted(Collections.reverseOrder(Comparator.comparingInt(List::size)))
                .collect(
                        ArrayList::new,
                        (ArrayList<List<Long>> paths, List<Long> newPath) -> {
                            final boolean isCovered = paths.stream()
                                    .anyMatch(path -> containsExactly(path, newPath));
                            if (!isCovered) {
                                paths.add(newPath);
                            }
                        },
                        ArrayList::addAll
                );
    }

    private static <T> boolean containsExactly(final List<T> lhs, final List<T> rhs) {
        final int lhsSize = lhs.size();
        final int rhsSize = rhs.size();
        final int maxSize = Math.min(lhsSize, rhsSize);

        if (lhsSize > rhsSize) {
            return Objects.equals(lhs.subList(0, maxSize), rhs);
        } else if (lhsSize < rhsSize) {
            return Objects.equals(lhs, rhs.subList(0, maxSize));
        }

        return Objects.equals(lhs, rhs);
    }

    public record DependencyNode(
            @Nullable Long id,
            @Nullable String version,
            @Nullable Boolean found,
            @Nullable List<Long> path) {
    }

    record CompositeDependencyNodeFilter(
            List<String> sqlFilters,
            Map<String, Object> sqlFilterParams,
            List<String> sqlSelectColumns,
            List<Predicate<DependencyNode>> inMemoryFilters) {

        private static final String VALUE_PREFIX_REGEX = "re:";
        private static final String VALUE_PREFIX_VERS = "vers:";

        static CompositeDependencyNodeFilter of(final Component component) {
            final var sqlFilters = new ArrayList<String>();
            final var sqlFilterParams = new HashMap<String, Object>();
            final var sqlSelectColumns = new ArrayList<String>();
            final var inMemoryFilters = new ArrayList<Predicate<DependencyNode>>();

            if (!component.getUuid().isBlank()) {
                sqlFilters.add("\"UUID\" = :uuid");
                sqlFilterParams.put("uuid", component.getUuid());
            }
            if (!component.getGroup().isBlank()) {
                if (component.getGroup().startsWith(VALUE_PREFIX_REGEX)) {
                    sqlFilters.add("\"GROUP\" ~ :groupRegex");
                    sqlFilterParams.put("groupRegex", substringAfter(component.getGroup(), VALUE_PREFIX_REGEX));
                } else {
                    sqlFilters.add("\"GROUP\" = :group");
                    sqlFilterParams.put("group", component.getGroup());
                }
            }
            if (!component.getName().isBlank()) {
                if (component.getName().startsWith(VALUE_PREFIX_REGEX)) {
                    sqlFilters.add("\"NAME\" ~ :nameRegex");
                    sqlFilterParams.put("nameRegex", substringAfter(component.getName(), VALUE_PREFIX_REGEX));
                } else {
                    sqlFilters.add("\"NAME\" = :name");
                    sqlFilterParams.put("name", component.getName());
                }
            }
            if (!component.getVersion().isBlank()) {
                if (component.getVersion().startsWith(VALUE_PREFIX_REGEX)) {
                    sqlFilters.add("\"VERSION\" ~ :versionRegex");
                    sqlFilterParams.put("versionRegex", substringAfter(component.getVersion(), VALUE_PREFIX_REGEX));
                } else if (component.getVersion().startsWith(VALUE_PREFIX_VERS)) {
                    final Vers vers = Vers.parse(component.getVersion());
                    inMemoryFilters.add(node -> node.version() != null && vers.contains(node.version()));
                    sqlSelectColumns.add("\"VERSION\"");
                } else {
                    sqlFilters.add("\"VERSION\" = :version");
                    sqlFilterParams.put("version", component.getVersion());
                }
            }
            if (!component.getClassifier().isBlank()) {
                sqlFilters.add("\"CLASSIFIER\" = :classifier");
                sqlFilterParams.put("classifier", component.getClassifier());
            }
            if (!component.getCpe().isBlank()) {
                if (component.getCpe().startsWith(VALUE_PREFIX_REGEX)) {
                    sqlFilters.add("\"CPE\" ~ :cpeRegex");
                    sqlFilterParams.put("cpeRegex", substringAfter(component.getCpe(), VALUE_PREFIX_REGEX));
                } else {
                    sqlFilters.add("\"CPE\" = :cpe");
                    sqlFilterParams.put("cpe", component.getCpe());
                }
            }
            if (!component.getPurl().isBlank()) {
                if (component.getPurl().startsWith(VALUE_PREFIX_REGEX)) {
                    sqlFilters.add("\"PURL\" ~ :purlRegex");
                    sqlFilterParams.put("purlRegex", substringAfter(component.getPurl(), VALUE_PREFIX_REGEX));
                } else {
                    sqlFilters.add("\"PURL\" = :purl");
                    sqlFilterParams.put("purl", component.getPurl());
                }
            }
            if (!component.getSwidTagId().isBlank()) {
                if (component.getSwidTagId().startsWith(VALUE_PREFIX_REGEX)) {
                    sqlFilters.add("\"SWIDTAGID\" ~ :swidTagIdRegex");
                    sqlFilterParams.put("swidTagIdRegex", substringAfter(component.getSwidTagId(), VALUE_PREFIX_REGEX));
                } else {
                    sqlFilters.add("\"SWIDTAGID\" = :swidTagId");
                    sqlFilterParams.put("swidTagId", component.getSwidTagId());
                }
            }
            if (component.hasIsInternal()) {
                if (component.getIsInternal()) {
                    sqlFilters.add("\"INTERNAL\" = TRUE");
                } else {
                    sqlFilters.add("(\"INTERNAL\" IS NULL OR \"INTERNAL\" = FALSE)");
                }
            }

            return new CompositeDependencyNodeFilter(sqlFilters, sqlFilterParams, sqlSelectColumns, inMemoryFilters);
        }

        boolean hasSqlFilters() {
            return sqlFilters != null && !sqlFilters.isEmpty();
        }

        boolean hasInMemoryFilters() {
            return inMemoryFilters != null && !inMemoryFilters.isEmpty();
        }

        String sqlFiltersConjunctive() {
            return String.join(" AND ", sqlFilters);
        }

        Predicate<DependencyNode> inMemoryFiltersConjunctive() {
            return inMemoryFilters.stream().reduce(Predicate::and).orElse(node -> true);
        }

    }

}