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

import alpine.model.Team;
import alpine.persistence.PaginatedResult;
import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.core.type.TypeReference;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.Tag;
import org.dependencytrack.persistence.jdbi.command.CloneProjectCommand;
import org.dependencytrack.persistence.jdbi.mapping.ExternalReferenceMapper;
import org.dependencytrack.persistence.jdbi.mapping.OrganizationalContactMapper;
import org.dependencytrack.persistence.jdbi.mapping.OrganizationalEntityMapper;
import org.dependencytrack.persistence.jdbi.query.ListProjectsConciseQuery;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.mapper.reflect.BeanMapper;
import org.jdbi.v3.core.mapper.reflect.ColumnName;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.core.statement.UnableToExecuteStatementException;
import org.jdbi.v3.json.Json;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterColumnMapper;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.customizer.AllowUnusedBindings;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.customizer.DefineNamedBindings;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.Nullable;
import org.postgresql.util.PSQLException;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.deserializeJson;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

/**
 * @since 5.0.0
 */
@RegisterConstructorMapper(ProjectDao.ConciseProjectListRow.class)
public interface ProjectDao extends SqlObject {

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="nameFilter" type="Boolean" -->
            <#-- @ftlvariable name="versionFilter" type="Boolean" -->
            <#-- @ftlvariable name="classifierFilter" type="Boolean" -->
            <#-- @ftlvariable name="tagFilter" type="Boolean" -->
            <#-- @ftlvariable name="teamFilter" type="Boolean" -->
            <#-- @ftlvariable name="activeFilter" type="Boolean" -->
            <#-- @ftlvariable name="onlyRootFilter" type="Boolean" -->
            <#-- @ftlvariable name="parentUuidFilter" type="Boolean" -->
            <#-- @ftlvariable name="includeMetrics" type="Boolean" -->
            <#-- @ftlvariable name="apiFilterParameter" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="apiParentProjectAclCondition" type="String" -->
            SELECT "PROJECT"."ID" AS "id"
                 , "PROJECT"."UUID" AS "uuid"
                 , "GROUP" AS "group"
                 , "NAME" AS "name"
                 , "VERSION" AS "version"
                 , "PROJECT"."CLASSIFIER" AS "classifier"
                 , "PROJECT"."INACTIVE_SINCE" AS "inactiveSince"
                 , "PROJECT"."IS_LATEST" AS "isLatest"
                 , "PROJECT"."COLLECTION_LOGIC" AS "collectionLogic"
                 , "PROJECT"."COLLECTION_TAG_ID" AS "collectionTagId"
                 , (SELECT ARRAY_AGG("TAG"."NAME")
                      FROM "TAG"
                     INNER JOIN "PROJECTS_TAGS"
                        ON "PROJECTS_TAGS"."TAG_ID" = "TAG"."ID"
                     WHERE "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID") AS "tags"
                 , (SELECT ARRAY_AGG("TEAM"."NAME")
                      FROM "TEAM"
                     INNER JOIN "PROJECT_ACCESS_TEAMS"
                        ON "PROJECT_ACCESS_TEAMS"."TEAM_ID" = "TEAM"."ID"
                     WHERE "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = "PROJECT"."ID") AS "teams"
                 , "PROJECT"."LAST_BOM_IMPORTED" AS "lastBomImport"
                 , "PROJECT"."LAST_BOM_IMPORTED_FORMAT" AS "lastBomImportFormat"
                 , "PROJECT"."LAST_RISKSCORE" AS "lastRiskScore"
                 , (SELECT EXISTS(
                     SELECT 1
                       FROM "PROJECT" AS "CHILD_PROJECT"
                      WHERE "CHILD_PROJECT"."PARENT_PROJECT_ID" = "PROJECT"."ID")) AS "hasChildren"
            <#if includeMetrics>
                 , (SELECT TO_JSONB(m)
                      FROM (
                        SELECT "COMPONENTS"
                             , "CRITICAL"
                             , "HIGH"
                             , "LOW"
                             , "MEDIUM"
                             , "POLICYVIOLATIONS_FAIL"
                             , "POLICYVIOLATIONS_INFO"
                             , "POLICYVIOLATIONS_LICENSE_TOTAL"
                             , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
                             , "POLICYVIOLATIONS_SECURITY_TOTAL"
                             , "POLICYVIOLATIONS_TOTAL"
                             , "POLICYVIOLATIONS_WARN"
                             , "RISKSCORE"
                             , "UNASSIGNED_SEVERITY"
                             , "VULNERABILITIES"
                          FROM "PROJECTMETRICS"
                         WHERE "PROJECTMETRICS"."PROJECT_ID" = "PROJECT"."ID"
                           AND "PROJECT"."COLLECTION_LOGIC" IS NULL
                         ORDER BY "PROJECTMETRICS"."LAST_OCCURRENCE" DESC
                         LIMIT 1
                      ) AS m
                   ) AS "metrics"
            </#if>
                 , COUNT(*) OVER() AS "totalCount"
              FROM "PROJECT"
             WHERE ${apiProjectAclCondition}
            <#if nameFilter>
               AND "PROJECT"."NAME" = :nameFilter
            </#if>
            <#if versionFilter>
               AND "PROJECT"."VERSION" = :versionFilter
            </#if>
            <#if classifierFilter>
               AND "PROJECT"."CLASSIFIER" = :classifierFilter
            </#if>
            <#if tagFilter>
               AND EXISTS(
                 SELECT 1
                   FROM "PROJECTS_TAGS"
                  INNER JOIN "TAG"
                     ON "TAG"."ID" = "PROJECTS_TAGS"."TAG_ID"
                  WHERE "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
                    AND "TAG"."NAME" = :tagFilter)
            </#if>
            <#if teamFilter>
               AND EXISTS(
                 SELECT 1
                   FROM "PROJECT_ACCESS_TEAMS"
                  INNER JOIN "TEAM"
                     ON "TEAM"."ID" = "PROJECT_ACCESS_TEAMS"."TEAM_ID"
                  WHERE "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = "PROJECT"."ID"
                    AND "TEAM"."NAME" = :teamFilter)
            </#if>
            <#if activeFilter && activeFilter == true>
                AND "PROJECT"."INACTIVE_SINCE" IS NULL
            </#if>
            <#if onlyRootFilter>
               AND (NOT :onlyRootFilter OR "PROJECT"."PARENT_PROJECT_ID" IS NULL)
            <#elseif parentUuidFilter>
               AND EXISTS(
                     SELECT 1
                       FROM "PROJECT" AS "PARENT_PROJECT"
                      WHERE "PARENT_PROJECT"."ID" = "PROJECT"."PARENT_PROJECT_ID"
                        AND "PARENT_PROJECT"."UUID" = :parentUuidFilter
                        AND ${apiParentProjectAclCondition})
            </#if>
            <#if apiFilterParameter??>
               AND (LOWER("PROJECT"."NAME") LIKE ('%' || LOWER(${apiFilterParameter}) || '%')
                    OR EXISTS (SELECT 1 FROM "TAG" WHERE "TAG"."NAME" = ${apiFilterParameter}))
            </#if>
            <#if apiOrderByClause??>
              ${apiOrderByClause}
            <#else>
             ORDER BY "name" ASC, "version" DESC
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @DefineNamedBindings
    @DefineApiProjectAclCondition(
            name = "apiParentProjectAclCondition",
            projectIdColumn = "\"PARENT_PROJECT\".\"ID\""
    )
    @AllowApiOrdering(alwaysBy = "id", by = {
            @AllowApiOrdering.Column(name = "id"),
            @AllowApiOrdering.Column(name = "group"),
            @AllowApiOrdering.Column(name = "name"),
            @AllowApiOrdering.Column(name = "version"),
            @AllowApiOrdering.Column(name = "classifier"),
            @AllowApiOrdering.Column(name = "inactiveSince"),
            @AllowApiOrdering.Column(name = "isLatest"),
            @AllowApiOrdering.Column(name = "lastBomImport"),
            @AllowApiOrdering.Column(name = "lastBomImportFormat"),
            @AllowApiOrdering.Column(name = "lastRiskScore")
    })
    List<ConciseProjectListRow> queryPageConcise(
            @Bind String nameFilter,
            @Bind String versionFilter,
            @Bind String classifierFilter,
            @Bind String tagFilter,
            @Bind String teamFilter,
            @Bind Boolean activeFilter,
            @Bind Boolean onlyRootFilter,
            @Bind UUID parentUuidFilter,
            @Define boolean includeMetrics);

    default List<ConciseProjectListRow> getPageConcise(ListProjectsConciseQuery query) {
        List<ConciseProjectListRow> rows = queryPageConcise(
                query.nameFilter(),
                query.versionFilter(),
                query.classifierFilter(),
                query.tagFilter(),
                query.teamFilter(),
                query.activeFilter(),
                query.onlyRootFilter(),
                query.parentUuidFilter(),
                query.includeMetrics());
        if (!query.includeMetrics() || rows.isEmpty()) {
            return rows;
        }

        // Metrics of collection projects cannot reasonably be queried inline.
        // If this result set contains collections, query their metrics separately.
        // Note that collection metrics are retrieved in bulk, and does not cause N+1.
        final Set<Long> collectionIds = rows.stream()
                .filter(row -> row.collectionLogic() != null && row.metrics() == null)
                .map(ConciseProjectListRow::id)
                .collect(Collectors.toSet());
        if (collectionIds.isEmpty()) {
            return rows;
        }

        final Map<Long, ProjectMetrics> collectionMetricsById = getHandle()
                .attach(MetricsDao.class)
                .getMostRecentCollectionProjectMetrics(collectionIds)
                .stream()
                .collect(Collectors.toMap(ProjectMetrics::getProjectId, Function.identity()));

        return rows.stream()
                .map(row -> {
                    final ProjectMetrics pm = collectionMetricsById.get(row.id());
                    return pm != null
                            ? row.withMetrics(ConciseProjectMetricsRow.of(pm))
                            : row;
                })
                .toList();
    }

    record ConciseProjectListRow(
            long id,
            UUID uuid,
            String group,
            String name,
            String version,
            String classifier,
            @Nullable Instant inactiveSince,
            boolean isLatest,
            @Nullable ProjectCollectionLogic collectionLogic,
            @Nullable Long collectionTagId,
            List<String> tags,
            List<String> teams,
            @Nullable Instant lastBomImport,
            @Nullable String lastBomImportFormat,
            @Nullable Double lastRiskScore,
            boolean hasChildren,
            @Nullable @Json ConciseProjectMetricsRow metrics,
            long totalCount) {

        ConciseProjectListRow withMetrics(@Nullable ConciseProjectMetricsRow metrics) {
            return new ConciseProjectListRow(
                    this.id,
                    this.uuid,
                    this.group,
                    this.name,
                    this.version,
                    this.classifier,
                    this.inactiveSince,
                    this.isLatest,
                    this.collectionLogic,
                    this.collectionTagId,
                    this.tags,
                    this.teams,
                    this.lastBomImport,
                    this.lastBomImportFormat,
                    this.lastRiskScore,
                    this.hasChildren,
                    metrics,
                    this.totalCount);
        }

    }

    record ConciseProjectMetricsRow(
            int components,
            int critical,
            int high,
            int low,
            int medium,
            @JsonAlias("policyviolations_fail") int policyViolationsFail,
            @JsonAlias("policyviolations_info") int policyViolationsInfo,
            @JsonAlias("policyviolations_license_total") int policyViolationsLicenseTotal,
            @JsonAlias("policyviolations_operational_total") int policyViolationsOperationalTotal,
            @JsonAlias("policyviolations_security_total") int policyViolationsSecurityTotal,
            @JsonAlias("policyviolations_total") int policyViolationsTotal,
            @JsonAlias("policyviolations_warn") int policyViolationsWarn,
            @JsonAlias("riskscore") double riskScore,
            @JsonAlias("unassigned_severity") int unassigned,
            int vulnerabilities) {

        static ConciseProjectMetricsRow of(ProjectMetrics pm) {
            return new ConciseProjectMetricsRow(
                    pm.getComponents(),
                    pm.getCritical(),
                    pm.getHigh(),
                    pm.getLow(),
                    pm.getMedium(),
                    pm.getPolicyViolationsFail(),
                    pm.getPolicyViolationsInfo(),
                    pm.getPolicyViolationsLicenseTotal(),
                    pm.getPolicyViolationsOperationalTotal(),
                    pm.getPolicyViolationsSecurityTotal(),
                    pm.getPolicyViolationsTotal(),
                    pm.getPolicyViolationsWarn(),
                    pm.getInheritedRiskScore(),
                    pm.getUnassigned(),
                    pm.getVulnerabilities());
        }

    }

    record ProjectListRow(Project project, long totalCount) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="nameFilter" type="String" -->
            <#-- @ftlvariable name="classifierFilter" type="Boolean" -->
            <#-- @ftlvariable name="teamFilter" type="String" -->
            <#-- @ftlvariable name="tagFilter" type="String" -->
            <#-- @ftlvariable name="notAssignedToTeamWithUuid" type="String" -->
            <#-- @ftlvariable name="onlyRoot" type="Boolean" -->
            <#-- @ftlvariable name="apiFilterParameter" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="apiParentProjectAclCondition" type="String" -->
            SELECT "PROJECT"."ID" AS "id"
                 , "PROJECT"."CLASSIFIER"
                 , "PROJECT"."CPE"
                 , "PROJECT"."DESCRIPTION"
                 , "PROJECT"."DIRECT_DEPENDENCIES" AS "directDependencies"
                 , "PROJECT"."EXTERNAL_REFERENCES" AS "externalReferences"
                 , "PROJECT"."GROUP"
                 , "PROJECT"."LAST_BOM_IMPORTED" AS "lastBomImport"
                 , "PROJECT"."LAST_BOM_IMPORTED_FORMAT" AS "lastBomImportFormat"
                 , "PROJECT"."LAST_RISKSCORE" AS "lastInheritedRiskScore"
                 , "PROJECT"."NAME" AS "name"
                 , "PROJECT"."PUBLISHER"
                 , "PROJECT"."PURL" AS "projectPurl"
                 , "PROJECT"."SWIDTAGID"
                 , "PROJECT"."UUID"
                 , "PROJECT"."VERSION" AS "version"
                 , "PROJECT"."SUPPLIER"
                 , "PROJECT"."MANUFACTURER"
                 , "PROJECT"."AUTHORS"
                 , "PROJECT"."IS_LATEST" AS "isLatest"
                 , "PROJECT"."INACTIVE_SINCE" AS "inactiveSince"
                 , "PROJECT"."COLLECTION_LOGIC" AS "collectionLogic"
                 , (SELECT JSONB_AGG(JSONB_BUILD_OBJECT('id', "ID", 'name', "NAME"))
                        FROM "TAG"
                        INNER JOIN "PROJECTS_TAGS"
                            ON "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
                        WHERE "TAG"."ID" = "PROJECTS_TAGS"."TAG_ID"
                    ) AS "tagsJson"
                 , (SELECT JSONB_AGG(JSONB_BUILD_OBJECT('id', "ID", 'name', "NAME"))
                        FROM "TEAM"
                        INNER JOIN "PROJECT_ACCESS_TEAMS"
                            ON "PROJECT_ACCESS_TEAMS"."TEAM_ID" = "TEAM"."ID"
                        WHERE "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = "PROJECT"."ID"
                    ) AS "teamsJson"
                 , COUNT(*) OVER() AS "totalCount"
              FROM "PROJECT"
             WHERE ${apiProjectAclCondition}
            <#if nameFilter>
               AND "PROJECT"."NAME" = :nameFilter
            </#if>
            <#if classifierFilter>
               AND "PROJECT"."CLASSIFIER" = :classifierFilter
            </#if>
            <#if tagFilter>
               AND EXISTS(
                 SELECT 1
                   FROM "PROJECTS_TAGS"
                  INNER JOIN "TAG"
                     ON "TAG"."ID" = "PROJECTS_TAGS"."TAG_ID"
                  WHERE "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
                    AND "TAG"."NAME" = :tagFilter)
            </#if>
            <#if teamFilter>
               AND EXISTS(
                 SELECT 1
                   FROM "PROJECT_ACCESS_TEAMS"
                  INNER JOIN "TEAM"
                     ON "TEAM"."ID" = "PROJECT_ACCESS_TEAMS"."TEAM_ID"
                  WHERE "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = "PROJECT"."ID"
                    AND "TEAM"."NAME" = :teamFilter)
            </#if>
            <#if notAssignedToTeamWithUuid>
               AND NOT EXISTS(
                 SELECT 1
                   FROM "PROJECT_ACCESS_TEAMS"
                  INNER JOIN "TEAM"
                     ON "TEAM"."ID" = "PROJECT_ACCESS_TEAMS"."TEAM_ID"
                  WHERE "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = "PROJECT"."ID"
                    AND "TEAM"."UUID" = :notAssignedToTeamWithUuid)
            </#if>
            <#if excludeInactive>
                AND "PROJECT"."INACTIVE_SINCE" IS NULL
            </#if>
            <#if onlyRoot>
               AND ("PROJECT"."PARENT_PROJECT_ID" IS NULL)
            </#if>
            <#if apiFilterParameter??>
               AND (LOWER("PROJECT"."NAME") LIKE ('%' || LOWER(${apiFilterParameter}) || '%')
                    OR EXISTS (SELECT 1 FROM "TAG" WHERE "TAG"."NAME" = ${apiFilterParameter}))
            </#if>
            <#if apiOrderByClause??>
                ${apiOrderByClause}
            <#else>
                ORDER BY "name" ASC, "version" DESC
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @DefineNamedBindings
    @AllowUnusedBindings
    @DefineApiProjectAclCondition(
            name = "apiParentProjectAclCondition",
            projectIdColumn = "\"PARENT_PROJECT\".\"ID\""
    )
    @AllowApiOrdering(alwaysBy = "id", by = {
            @AllowApiOrdering.Column(name = "id"),
            @AllowApiOrdering.Column(name = "name"),
            @AllowApiOrdering.Column(name = "version")
    })
    @RegisterColumnMapper(ExternalReferenceMapper.class)
    @RegisterColumnMapper(OrganizationalEntityMapper.class)
    @RegisterColumnMapper(OrganizationalContactMapper.class)
    @RegisterRowMapper(ProjectListRowMapper.class)
    List<ProjectListRow> getProjects(
            @Bind String nameFilter,
            @Bind String classifierFilter,
            @Bind String tagFilter,
            @Bind String teamFilter,
            @Bind String notAssignedToTeamWithUuid,
            @Define boolean excludeInactive,
            @Define boolean onlyRoot
    );

    default PaginatedResult getProjects(
            String nameFilter,
            String classifierFilter,
            String tagFilter,
            String teamFilter,
            String notAssignedToTeamWithUuid,
            boolean excludeInactive,
            boolean onlyRoot,
            boolean includeMetrics) {
        final List<ProjectListRow> projectListRows = getProjects(
                nameFilter,
                classifierFilter,
                tagFilter,
                teamFilter,
                notAssignedToTeamWithUuid,
                excludeInactive,
                onlyRoot);
        final long totalCount = !projectListRows.isEmpty()
                ? projectListRows.getFirst().totalCount()
                : 0;
        final List<Project> projects = projectListRows.stream()
                .map(ProjectListRow::project)
                .toList();

        if (includeMetrics) {
            final Map<Long, Project> projectById = projects.stream()
                    .filter(project -> project.getCollectionLogic() == null)
                    .collect(Collectors.toMap(Project::getId, Function.identity()));
            final List<ProjectMetrics> metricsList = getHandle()
                    .attach(MetricsDao.class)
                    .getMostRecentProjectMetrics(projectById.keySet());

            for (final ProjectMetrics metrics : metricsList) {
                final Project project = projectById.get(metrics.getProjectId());
                if (project != null) {
                    project.setMetrics(metrics);
                }
            }

            final Map<Long, Project> collectionById = projects.stream()
                    .filter(project -> project.getCollectionLogic() != null)
                    .collect(Collectors.toMap(Project::getId, Function.identity()));
            if (!collectionById.isEmpty()) {
                final List<ProjectMetrics> collectionMetrics = getHandle()
                        .attach(MetricsDao.class)
                        .getMostRecentCollectionProjectMetrics(collectionById.keySet());

                for (final ProjectMetrics metrics : collectionMetrics) {
                    final Project collection = collectionById.get(metrics.getProjectId());
                    if (collection != null) {
                        collection.setMetrics(metrics);
                    }
                }
            }
        }

        return (new PaginatedResult()).objects(projects).total(totalCount);
    }

    @SqlUpdate("""
            DELETE
              FROM "PROJECT"
             WHERE "UUID" = :projectUuid
            """)
    int deleteProject(@Bind final UUID projectUuid);

    @SqlUpdate("""
            WITH cte_locked AS (
              SELECT "ID"
                FROM "PROJECT"
               WHERE ${apiProjectAclCondition}
                 AND "UUID" = ANY(:projectUuids)
               ORDER BY "ID"
                 FOR UPDATE
            )
            DELETE
              FROM "PROJECT"
             WHERE "ID" IN (SELECT "ID" FROM cte_locked)
            RETURNING "UUID"
            """)
    @GetGeneratedKeys
    Set<UUID> deleteProjects(@Bind Collection<UUID> projectUuids);

    @SqlQuery("""
             WITH "CTE" AS (
               SELECT "ID"
                 FROM "PROJECT"
                WHERE "INACTIVE_SINCE" < :retentionCutOff
                ORDER BY "INACTIVE_SINCE"
                LIMIT :batchSize
             )
             DELETE
               FROM "PROJECT"
              WHERE "ID" IN (SELECT "ID" FROM "CTE")
              RETURNING "NAME", "VERSION", "INACTIVE_SINCE", "UUID"
            """)
    @RegisterConstructorMapper(DeletedProject.class)
    List<DeletedProject> deleteInactiveProjectsForRetentionDuration(@Bind final Instant retentionCutOff, @Bind final int batchSize);

    record DeletedProject(@ColumnName("NAME") String name,
                          @ColumnName("VERSION") String version,
                          @ColumnName("INACTIVE_SINCE") Instant inactiveSince,
                          @ColumnName("UUID") UUID uuid) {
    }

    @SqlQuery("""
            WITH cte_candidates AS (
              SELECT "ID"
                FROM (
                  SELECT "ID"
                       , ROW_NUMBER() OVER (PARTITION BY "NAME" ORDER BY "INACTIVE_SINCE" DESC) AS rn
                    FROM "PROJECT"
                   WHERE "INACTIVE_SINCE" IS NOT NULL
                ) AS ranked
               WHERE rn > :versionCountThreshold
               LIMIT :batchSize
            )
            DELETE
              FROM "PROJECT"
             WHERE "ID" IN (SELECT "ID" FROM cte_candidates)
            RETURNING "NAME"
                    , "VERSION"
                    , "INACTIVE_SINCE"
                    , "UUID"
            """)
    @RegisterConstructorMapper(DeletedProject.class)
    List<DeletedProject> deleteExcessProjectVersions(@Bind int versionCountThreshold, @Bind int batchSize);

    record ProjectInfoRow(long id, boolean isCollection) {
    }

    @SqlQuery("""
            SELECT "ID"
                 , "COLLECTION_LOGIC" IS NOT NULL AS is_collection
              FROM "PROJECT"
             WHERE "UUID" = :projectUuid
            """)
    @RegisterConstructorMapper(ProjectInfoRow.class)
    @Nullable
    ProjectInfoRow getProjectInfo(@Bind UUID projectUuid);

    default @Nullable Long getProjectId(UUID projectUuid) {
        final ProjectInfoRow info = getProjectInfo(projectUuid);
        return info != null ? info.id() : null;
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT ${apiProjectAclCondition}
              FROM "PROJECT"
             WHERE "UUID" = :projectUuid
            """)
    Boolean isAccessible(@Bind UUID projectUuid);

    /**
     * @param command The clone command.
     * @return The {@link UUID} of the cloned project.
     * @throws NoSuchElementException When the source project does not exist.
     * @throws AlreadyExistsException When a project with the target version already exists.
     * @since 5.0.0
     */
    default UUID cloneProject(final CloneProjectCommand command) {
        final Query query = getHandle().createQuery(/* language=SQL */ """
                SELECT clone_project(
                  :sourceProjectUuid
                , :targetProjectVersion
                , :targetProjectVersionIsLatest
                , :includeAcl
                , :includeComponents
                , :includeFindings
                , :includeFindingsAuditHistory
                , :includePolicyViolations
                , :includePolicyViolationsAuditHistory
                , :includeProperties
                , :includeServices
                , :includeTags
                );
                """);

        try {
            return query
                    .bindMethods(command)
                    .mapTo(UUID.class)
                    .one();
        } catch (UnableToExecuteStatementException e) {
            if (e.getCause() instanceof final PSQLException pe
                    && pe.getServerErrorMessage() != null
                    && pe.getServerErrorMessage().getMessage() != null) {
                if (pe.getServerErrorMessage().getMessage().startsWith("Source project does not exist")) {
                    throw new NoSuchElementException(pe.getServerErrorMessage().getMessage(), pe);
                } else if (pe.getServerErrorMessage().getMessage().startsWith("Target project version already exists")) {
                    throw new AlreadyExistsException(pe.getServerErrorMessage().getMessage(), pe);
                }
            }

            throw e;
        }
    }

    /**
     * @since 5.0.0
     */
    @SqlUpdate("""
            UPDATE "PROJECT"
               SET "LAST_VULNERABILITY_ANALYSIS" = NOW()
             WHERE "UUID" = :uuid
            """)
    void updateLastVulnAnalysis(@Bind UUID uuid);

    class ProjectListRowMapper implements RowMapper<ProjectListRow> {

        private static final TypeReference<Set<Tag>> TAGS_TYPE_REF = new TypeReference<>() {
        };
        private static final TypeReference<Set<Team>> TEAMS_TYPE_REF = new TypeReference<>() {
        };

        private final RowMapper<Project> projectMapper = BeanMapper.of(Project.class);

        @Override
        public ProjectListRow map(final ResultSet rs, final StatementContext ctx) throws SQLException {
            final Project project = projectMapper.map(rs, ctx);
            maybeSet(rs, "projectPurl", ResultSet::getString, project::setPurl);
            maybeSet(rs, "teamsJson", (ignored, columnName) ->
                    deserializeJson(rs, columnName, TEAMS_TYPE_REF), project::setAccessTeams);
            maybeSet(rs, "tagsJson", (ignored, columnName) ->
                    deserializeJson(rs, columnName, TAGS_TYPE_REF), project::setTags);
            final ProjectListRow projectListRow = new ProjectListRow(project, rs.getInt("totalCount"));
            return projectListRow;
        }
    }
}
