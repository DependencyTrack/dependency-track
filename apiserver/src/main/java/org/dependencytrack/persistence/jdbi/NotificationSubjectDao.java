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

import org.dependencytrack.model.FindingKey;
import org.dependencytrack.notification.proto.v1.Component;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerableDependencySubject;
import org.dependencytrack.notification.proto.v1.Policy;
import org.dependencytrack.notification.proto.v1.PolicyCondition;
import org.dependencytrack.notification.proto.v1.PolicyViolation;
import org.dependencytrack.notification.proto.v1.PolicyViolationSubject;
import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.notification.proto.v1.Vulnerability;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.persistence.jdbi.mapping.NotificationBomRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationComponentRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationProjectRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectNewVulnerabilityRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectProjectAuditChangeRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationVulnerabilityRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil;
import org.dependencytrack.persistence.jdbi.query.GetProjectAuditChangeNotificationSubjectQuery;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMappers;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SequencedCollection;
import java.util.UUID;
import java.util.stream.Collectors;

@RegisterRowMappers({
        @RegisterRowMapper(NotificationBomRowMapper.class),
        @RegisterRowMapper(NotificationComponentRowMapper.class),
        @RegisterRowMapper(NotificationProjectRowMapper.class),
        @RegisterRowMapper(NotificationVulnerabilityRowMapper.class)
})
public interface NotificationSubjectDao extends SqlObject {

    @SqlQuery("""
            SELECT c."UUID" AS "componentUuid"
                 , c."GROUP" AS "componentGroup"
                 , c."NAME" AS "componentName"
                 , c."VERSION" AS "componentVersion"
                 , c."PURL" AS "componentPurl"
                 , c."MD5" AS "componentMd5"
                 , c."SHA1" AS "componentSha1"
                 , c."SHA_256" AS "componentSha256"
                 , c."SHA_512" AS "componentSha512"
                 , p."UUID" AS "projectUuid"
                 , p."NAME" AS "projectName"
                 , p."VERSION" AS "projectVersion"
                 , p."DESCRIPTION" AS "projectDescription"
                 , p."PURL" AS "projectPurl"
                 , (p."INACTIVE_SINCE" IS NULL) AS "isActive"
                 , (
                     SELECT ARRAY_AGG(DISTINCT t."NAME")
                       FROM "TAG" AS t
                      INNER JOIN "PROJECTS_TAGS" AS pt
                         ON pt."TAG_ID" = t."ID"
                      WHERE pt."PROJECT_ID" = p."ID"
                   ) AS "projectTags"
                 , v."UUID" AS "vulnUuid"
                 , v."VULNID" AS "vulnId"
                 , v."SOURCE" AS "vulnSource"
                 , v."TITLE" AS "vulnTitle"
                 , v."SUBTITLE" AS "vulnSubTitle"
                 , v."DESCRIPTION" AS "vulnDescription"
                 , v."RECOMMENDATION" AS "vulnRecommendation"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."CVSSV2SCORE"
                     ELSE v."CVSSV2BASESCORE"
                   END AS "vulnCvssV2BaseScore"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."CVSSV3SCORE"
                     ELSE v."CVSSV3BASESCORE"
                   END AS "vulnCvssV3BaseScore"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."CVSSV4SCORE"
                     ELSE v."CVSSV4SCORE"
                   END AS "vulnCvssV4Score"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."CVSSV2VECTOR"
                     ELSE v."CVSSV2VECTOR"
                   END AS "vulnCvssV2Vector"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."CVSSV3VECTOR"
                     ELSE v."CVSSV3VECTOR"
                   END AS "vulnCvssV3Vector"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."CVSSV4VECTOR"
                     ELSE v."CVSSV4VECTOR"
                   END AS "vulnCvssV4Vector"
                  -- TODO: Analysis only has a single score, but OWASP RR defines multiple.
                  --  How to handle this?
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."OWASPSCORE"
                     ELSE v."OWASPRRBUSINESSIMPACTSCORE"
                   END AS "vulnOwaspRrBusinessImpactScore"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."OWASPSCORE"
                     ELSE v."OWASPRRLIKELIHOODSCORE"
                   END AS "vulnOwaspRrLikelihoodScore"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."OWASPSCORE"
                     ELSE v."OWASPRRTECHNICALIMPACTSCORE"
                   END AS "vulnOwaspRrTechnicalImpactScore"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."OWASPVECTOR"
                     ELSE v."OWASPRRVECTOR"
                   END AS "vulnOwaspRrVector"
                 , COALESCE(a."SEVERITY", v."SEVERITY") AS "vulnSeverity"
                 , STRING_TO_ARRAY(v."CWES", ',') AS "vulnCwes"
                 , JSONB_VULN_ALIASES(v."SOURCE", v."VULNID") AS "vulnAliasesJson"
              FROM UNNEST(:componentIds, :vulnerabilityIds)
                AS req(component_id, vulnerability_id)
             INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                ON cv."COMPONENT_ID" = req.component_id
               AND cv."VULNERABILITY_ID" = req.vulnerability_id
             INNER JOIN "COMPONENT" AS c
                ON c."ID" = req.component_id
             INNER JOIN "PROJECT" AS p
                ON p."ID" = c."PROJECT_ID"
             INNER JOIN "VULNERABILITY" AS v
                ON v."ID" = req.vulnerability_id
              LEFT JOIN "ANALYSIS" AS a
                ON a."COMPONENT_ID" = req.component_id
               AND a."VULNERABILITY_ID" = req.vulnerability_id
             WHERE a."SUPPRESSED" IS DISTINCT FROM TRUE
            """)
    @RegisterRowMapper(NotificationSubjectNewVulnerabilityRowMapper.class)
    List<NewVulnerabilitySubject> getForNewVulnerabilities(List<Long> componentIds, List<Long> vulnerabilityIds);

    default List<NewVulnerableDependencySubject> getForNewVulnerableDependencies(Collection<Long> componentIds) {
        if (componentIds.isEmpty()) {
            return List.of();
        }

        final var componentRowMapper = new NotificationComponentRowMapper();
        final var projectRowMapper = new NotificationProjectRowMapper();
        final var vulnerabilityRowMapper = new NotificationVulnerabilityRowMapper();
        final var subjectBuilderByComponentUuid =
                new HashMap<UUID, NewVulnerableDependencySubject.Builder>(componentIds.size());

        getHandle()
                .createQuery("""
                        SELECT c."UUID" AS "componentUuid"
                             , c."GROUP" AS "componentGroup"
                             , c."NAME" AS "componentName"
                             , c."VERSION" AS "componentVersion"
                             , c."PURL" AS "componentPurl"
                             , c."MD5" AS "componentMd5"
                             , c."SHA1" AS "componentSha1"
                             , c."SHA_256" AS "componentSha256"
                             , c."SHA_512" AS "componentSha512"
                             , p."UUID" AS "projectUuid"
                             , p."NAME" AS "projectName"
                             , p."VERSION" AS "projectVersion"
                             , p."DESCRIPTION" AS "projectDescription"
                             , p."PURL" AS "projectPurl"
                             , (p."INACTIVE_SINCE" IS NULL) AS "isActive"
                             , (
                                 SELECT ARRAY_AGG(DISTINCT t."NAME")
                                   FROM "TAG" AS t
                                  INNER JOIN "PROJECTS_TAGS" AS pt
                                     ON pt."TAG_ID" = t."ID"
                                  WHERE pt."PROJECT_ID" = p."ID"
                               ) AS "projectTags"
                             , v."UUID" AS "vulnUuid"
                             , v."VULNID" AS "vulnId"
                             , v."SOURCE" AS "vulnSource"
                             , v."TITLE" AS "vulnTitle"
                             , v."SUBTITLE" AS "vulnSubTitle"
                             , v."DESCRIPTION" AS "vulnDescription"
                             , v."RECOMMENDATION" AS "vulnRecommendation"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL
                                 THEN a."CVSSV2SCORE"
                                 ELSE v."CVSSV2BASESCORE"
                               END AS "vulnCvssV2BaseScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL
                                 THEN a."CVSSV3SCORE"
                                 ELSE v."CVSSV3BASESCORE"
                               END AS "vulnCvssV3BaseScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL
                                 THEN a."CVSSV4SCORE"
                                 ELSE v."CVSSV4SCORE"
                               END AS "vulnCvssV4Score"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL
                                 THEN a."CVSSV2VECTOR"
                                 ELSE v."CVSSV2VECTOR"
                               END AS "vulnCvssV2Vector"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL
                                 THEN a."CVSSV3VECTOR"
                                 ELSE v."CVSSV3VECTOR"
                               END AS "vulnCvssV3Vector"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL
                                 THEN a."CVSSV4VECTOR"
                                 ELSE v."CVSSV4VECTOR"
                               END AS "vulnCvssV4Vector"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL
                                 THEN a."OWASPSCORE"
                                 ELSE v."OWASPRRBUSINESSIMPACTSCORE"
                               END AS "vulnOwaspRrBusinessImpactScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL
                                 THEN a."OWASPSCORE"
                                 ELSE v."OWASPRRLIKELIHOODSCORE"
                               END AS "vulnOwaspRrLikelihoodScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL
                                 THEN a."OWASPSCORE"
                                 ELSE v."OWASPRRTECHNICALIMPACTSCORE"
                               END AS "vulnOwaspRrTechnicalImpactScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL
                                 THEN a."OWASPVECTOR"
                                 ELSE v."OWASPRRVECTOR"
                               END AS "vulnOwaspRrVector"
                             , COALESCE(a."SEVERITY", v."SEVERITY") AS "vulnSeverity"
                             , STRING_TO_ARRAY(v."CWES", ',') AS "vulnCwes"
                             , JSONB_VULN_ALIASES(v."SOURCE", v."VULNID") AS "vulnAliasesJson"
                          FROM "COMPONENT" AS c
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = c."PROJECT_ID"
                         INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                            ON cv."COMPONENT_ID" = c."ID"
                         INNER JOIN "VULNERABILITY" AS v
                            ON v."ID" = cv."VULNERABILITY_ID"
                          LEFT JOIN "ANALYSIS" AS a
                            ON a."COMPONENT_ID" = c."ID"
                           AND a."VULNERABILITY_ID" = v."ID"
                         WHERE c."ID" = ANY(:componentIds)
                           AND EXISTS(
                                 SELECT 1
                                   FROM "FINDINGATTRIBUTION" AS fa
                                  WHERE fa."COMPONENT_ID" = c."ID"
                                    AND fa."VULNERABILITY_ID" = v."ID"
                                    AND fa."DELETED_AT" IS NULL
                               )
                           AND a."SUPPRESSED" IS DISTINCT FROM TRUE
                        """)
                .bindArray("componentIds", Long.class, componentIds)
                .reduceResultSet(subjectBuilderByComponentUuid, (accumulator, rs, ctx) -> {
                    final var componentUuid = rs.getObject("componentUuid", UUID.class);

                    NewVulnerableDependencySubject.Builder builder = accumulator.get(componentUuid);
                    if (builder == null) {
                        builder = NewVulnerableDependencySubject.newBuilder()
                                .setComponent(componentRowMapper.map(rs, ctx))
                                .setProject(projectRowMapper.map(rs, ctx));
                        accumulator.put(componentUuid, builder);
                    }

                    builder.addVulnerabilities(vulnerabilityRowMapper.map(rs, ctx));

                    return accumulator;
                });

        final var result = new ArrayList<NewVulnerableDependencySubject>(subjectBuilderByComponentUuid.size());
        subjectBuilderByComponentUuid.values().forEach(builder -> result.add(builder.build()));
        return result;
    }

    default List<VulnerabilityAnalysisDecisionChangeSubject> getForProjectAuditChanges(
            SequencedCollection<GetProjectAuditChangeNotificationSubjectQuery> queries) {
        if (queries.isEmpty()) {
            return List.of();
        }

        final var componentIds = new long[queries.size()];
        final var vulnDbIds = new long[queries.size()];
        final var analysisStates = new String[queries.size()];
        final var suppressions = new boolean[queries.size()];

        int i = 0;
        for (final GetProjectAuditChangeNotificationSubjectQuery query : queries) {
            componentIds[i] = query.componentId();
            vulnDbIds[i] = query.vulnId();
            analysisStates[i] = query.analysisState().name();
            suppressions[i] = query.suppressed();
            i++;
        }

        return getHandle()
                .createQuery("""
                        SELECT c."UUID" AS "componentUuid"
                             , c."GROUP" AS "componentGroup"
                             , c."NAME" AS "componentName"
                             , c."VERSION" AS "componentVersion"
                             , c."PURL" AS "componentPurl"
                             , c."MD5" AS "componentMd5"
                             , c."SHA1" AS "componentSha1"
                             , c."SHA_256" AS "componentSha256"
                             , c."SHA_512" AS "componentSha512"
                             , p."UUID" AS "projectUuid"
                             , p."NAME" AS "projectName"
                             , p."VERSION" AS "projectVersion"
                             , p."DESCRIPTION" AS "projectDescription"
                             , p."PURL" AS "projectPurl"
                             , (p."INACTIVE_SINCE" IS NULL) AS "isActive"
                             , (
                                 SELECT ARRAY_AGG(DISTINCT t."NAME")
                                   FROM "TAG" AS t
                                  INNER JOIN "PROJECTS_TAGS" AS pt
                                     ON pt."TAG_ID" = t."ID"
                                  WHERE pt."PROJECT_ID" = p."ID"
                               ) AS "projectTags"
                             , v."UUID" AS "vulnUuid"
                             , v."VULNID" AS "vulnId"
                             , v."SOURCE" AS "vulnSource"
                             , v."TITLE" AS "vulnTitle"
                             , v."SUBTITLE" AS "vulnSubTitle"
                             , v."DESCRIPTION" AS "vulnDescription"
                             , v."RECOMMENDATION" AS "vulnRecommendation"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV2SCORE"
                                 ELSE v."CVSSV2BASESCORE"
                               END AS "vulnCvssV2BaseScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV3SCORE"
                                 ELSE v."CVSSV3BASESCORE"
                               END AS "vulnCvssV3BaseScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV4SCORE"
                                 ELSE v."CVSSV4SCORE"
                               END AS "vulnCvssV4Score"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV2VECTOR"
                                 ELSE v."CVSSV2VECTOR"
                               END AS "vulnCvssV2Vector"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV3VECTOR"
                                 ELSE v."CVSSV3VECTOR"
                               END AS "vulnCvssV3Vector"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV4VECTOR"
                                 ELSE v."CVSSV4VECTOR"
                               END AS "vulnCvssV4Vector"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."OWASPSCORE"
                                 ELSE v."OWASPRRBUSINESSIMPACTSCORE"
                               END AS "vulnOwaspRrBusinessImpactScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."OWASPSCORE"
                                 ELSE v."OWASPRRLIKELIHOODSCORE"
                               END AS "vulnOwaspRrLikelihoodScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."OWASPSCORE"
                                 ELSE v."OWASPRRTECHNICALIMPACTSCORE"
                               END AS "vulnOwaspRrTechnicalImpactScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."OWASPVECTOR"
                                 ELSE v."OWASPRRVECTOR"
                               END AS "vulnOwaspRrVector"
                             , COALESCE(a."SEVERITY", v."SEVERITY") AS "vulnSeverity"
                             , STRING_TO_ARRAY(v."CWES", ',') AS "vulnCwes"
                             , JSONB_VULN_ALIASES(v."SOURCE", v."VULNID") AS "vulnAliasesJson"
                             , req.analysis_state AS "vulnAnalysisState"
                             , req.suppressed AS "isVulnAnalysisSuppressed"
                             , a."POLICY_ANNOTATIONS"::text AS "policyAnnotationsJson"
                             , format('/api/v1/vulnerability/source/%s/vuln/%s/projects', v."SOURCE", v."VULNID") AS "affectedProjectsApiUrl"
                             , format('/vulnerabilities/%s/%s/affectedProjects', v."SOURCE", v."VULNID") AS "affectedProjectsFrontendUrl"
                          FROM UNNEST(:componentIds, :vulnDbIds, :analysisStates, :suppressions) WITH ORDINALITY
                            AS req(component_id, vuln_db_id, analysis_state, suppressed, ord)
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = req.component_id
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = c."PROJECT_ID"
                         INNER JOIN "VULNERABILITY" AS v
                            ON v."ID" = req.vuln_db_id
                          LEFT JOIN "ANALYSIS" AS a
                            ON a."COMPONENT_ID" = req.component_id
                           AND a."VULNERABILITY_ID" = req.vuln_db_id
                         ORDER BY req.ord
                        """)
                .bind("componentIds", componentIds)
                .bind("vulnDbIds", vulnDbIds)
                .bind("analysisStates", analysisStates)
                .bind("suppressions", suppressions)
                .map(new NotificationSubjectProjectAuditChangeRowMapper())
                .list();
    }

    @SqlQuery("""
            SELECT p."UUID" AS "projectUuid"
                 , p."NAME" AS "projectName"
                 , p."VERSION" AS "projectVersion"
                 , p."DESCRIPTION" AS "projectDescription"
                 , p."PURL" AS "projectPurl"
                 , (p."INACTIVE_SINCE" IS NULL) AS "isActive"
                 , (
                     SELECT ARRAY_AGG(DISTINCT t."NAME")
                       FROM "TAG" AS t
                      INNER JOIN "PROJECTS_TAGS" AS pt
                         ON pt."TAG_ID" = t."ID"
                      WHERE pt."PROJECT_ID" = p."ID"
                   ) AS "projectTags"
              FROM "PROJECT" AS p
             WHERE p."UUID" = ANY(:projectUuids)
            """)
    List<Project> getProjects(@Bind Collection<UUID> projectUuids);

    /**
     * @since 5.0.0
     */
    default Map<Long, Project> getProjectsById(Collection<Long> ids) {
        if (ids.isEmpty()) {
            return Map.of();
        }

        return getHandle()
                .createQuery(/* language=SQL */ """
                        SELECT "ID"
                             , "UUID" AS "projectUuid"
                             , "NAME" AS "projectName"
                             , "VERSION" AS "projectVersion"
                             , "DESCRIPTION" AS "projectDescription"
                             , "PURL" AS "projectPurl"
                             , ("INACTIVE_SINCE" IS NULL) AS "isActive"
                             , (
                                 SELECT ARRAY_AGG(DISTINCT t."NAME")
                                   FROM "TAG" AS t
                                  INNER JOIN "PROJECTS_TAGS" AS pt
                                     ON pt."TAG_ID" = t."ID"
                                  WHERE pt."PROJECT_ID" = "PROJECT"."ID"
                               ) AS "projectTags"
                          FROM "PROJECT"
                         WHERE "ID" = ANY(:ids)
                        """)
                .bindArray("ids", Long.class, ids)
                .map((rs, ctx) -> Map.entry(
                        rs.getLong("ID"),
                        ctx.findRowMapperFor(Project.class).orElseThrow().map(rs, ctx)))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    /**
     * @since 5.0.0
     */
    default Map<Long, Component> getComponentsById(Collection<Long> ids) {
        if (ids.isEmpty()) {
            return Map.of();
        }

        return getHandle()
                .createQuery(/* language=SQL */ """
                        SELECT "ID"
                             , "UUID" AS "componentUuid"
                             , "GROUP" AS "componentGroup"
                             , "NAME" AS "componentName"
                             , "VERSION" AS "componentVersion"
                             , "PURL" AS "componentPurl"
                             , "MD5" AS "componentMd5"
                             , "SHA1" AS "componentSha1"
                             , "SHA_256" AS "componentSha256"
                             , "SHA_512" AS "componentSha512"
                          FROM "COMPONENT"
                         WHERE "ID" = ANY(:ids)
                        """)
                .bindArray("ids", Long.class, ids)
                .map((rs, ctx) -> Map.entry(
                        rs.getLong("ID"),
                        ctx.findRowMapperFor(Component.class).orElseThrow().map(rs, ctx)))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    /**
     * @since 5.0.0
     */
    default Map<FindingKey, Vulnerability> getVulnsByFindingKey(Collection<FindingKey> findingKeys) {
        if (findingKeys.isEmpty()) {
            return Map.of();
        }

        final var componentIds = new long[findingKeys.size()];
        final var vulnDbIds = new long[findingKeys.size()];

        int i = 0;
        for (final FindingKey findingKey : findingKeys) {
            componentIds[i] = findingKey.componentId();
            vulnDbIds[i] = findingKey.vulnDbId();
            i++;
        }

        return getHandle()
                .createQuery(/* language=SQL */ """
                        SELECT t.component_id
                             , t.vuln_db_id
                             , v."UUID" AS "vulnUuid"
                             , v."VULNID" AS "vulnId"
                             , v."SOURCE" AS "vulnSource"
                             , v."TITLE" AS "vulnTitle"
                             , v."SUBTITLE" AS "vulnSubTitle"
                             , v."DESCRIPTION" AS "vulnDescription"
                             , v."RECOMMENDATION" AS "vulnRecommendation"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV2SCORE"
                                 ELSE v."CVSSV2BASESCORE"
                               END AS "vulnCvssV2BaseScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV3SCORE"
                                 ELSE v."CVSSV3BASESCORE"
                               END AS "vulnCvssV3BaseScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV4SCORE"
                                 ELSE v."CVSSV4SCORE"
                               END AS "vulnCvssV4Score"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV2VECTOR"
                                 ELSE v."CVSSV2VECTOR"
                               END AS "vulnCvssV2Vector"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV3VECTOR"
                                 ELSE v."CVSSV3VECTOR"
                               END AS "vulnCvssV3Vector"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV4VECTOR"
                                 ELSE v."CVSSV4VECTOR"
                               END AS "vulnCvssV4Vector"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."OWASPSCORE"
                                 ELSE v."OWASPRRBUSINESSIMPACTSCORE"
                               END AS "vulnOwaspRrBusinessImpactScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."OWASPSCORE"
                                 ELSE v."OWASPRRLIKELIHOODSCORE"
                               END AS "vulnOwaspRrLikelihoodScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."OWASPSCORE"
                                 ELSE v."OWASPRRTECHNICALIMPACTSCORE"
                               END AS "vulnOwaspRrTechnicalImpactScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."OWASPVECTOR"
                                 ELSE v."OWASPRRVECTOR"
                               END AS "vulnOwaspRrVector"
                             , COALESCE(a."SEVERITY", v."SEVERITY") AS "vulnSeverity"
                             , STRING_TO_ARRAY(v."CWES", ',') AS "vulnCwes"
                             , JSONB_VULN_ALIASES(v."SOURCE", v."VULNID") AS "vulnAliasesJson"
                          FROM UNNEST(:componentIds, :vulnDbIds)
                            AS t(component_id, vuln_db_id)
                         INNER JOIN "VULNERABILITY" AS v
                            ON v."ID" = t.vuln_db_id
                          LEFT JOIN "ANALYSIS" AS a
                            ON a."COMPONENT_ID" = t.component_id
                           AND a."VULNERABILITY_ID" = t.vuln_db_id
                        """)
                .bind("componentIds", componentIds)
                .bind("vulnDbIds", vulnDbIds)
                .map((rs, ctx) -> Map.entry(
                        new FindingKey(rs.getLong("component_id"), rs.getLong("vuln_db_id")),
                        ctx.findRowMapperFor(Vulnerability.class).orElseThrow().map(rs, ctx)))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    default Map<Long, PolicyCondition> getPolicyConditionsById(Collection<Long> ids) {
        if (ids.isEmpty()) {
            return Map.of();
        }

        return getHandle()
                .createQuery(/* language=SQL */ """
                        SELECT pc."ID"
                             , pc."UUID"
                             , pc."SUBJECT"
                             , pc."OPERATOR"
                             , pc."VALUE"
                             , p."UUID" AS policy_uuid
                             , p."NAME" AS policy_name
                             , p."VIOLATIONSTATE" AS policy_violation_state
                          FROM "POLICYCONDITION" pc
                         INNER JOIN "POLICY" p
                            ON p."ID" = pc."POLICY_ID"
                         WHERE pc."ID" = ANY(:ids)
                        """)
                .bindArray("ids", Long.class, ids)
                .map((rs, ctx) -> Map.entry(
                        rs.getLong("ID"),
                        PolicyCondition.newBuilder()
                                .setUuid(rs.getString("UUID"))
                                .setSubject(rs.getString("SUBJECT"))
                                .setOperator(rs.getString("OPERATOR"))
                                .setValue(rs.getString("VALUE"))
                                .setPolicy(Policy.newBuilder()
                                        .setUuid(rs.getString("policy_uuid"))
                                        .setName(rs.getString("policy_name"))
                                        .setViolationState(rs.getString("policy_violation_state"))
                                        .build())
                                .build()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    default List<PolicyViolationSubject> getForNewPolicyViolations(Collection<Long> violationIds) {
        if (violationIds.isEmpty()) {
            return List.of();
        }

        final var componentRowMapper = new NotificationComponentRowMapper();
        final var projectRowMapper = new NotificationProjectRowMapper();

        return getHandle()
                .createQuery("""
                        SELECT pv."UUID" AS "violationUuid"
                             , pv."TYPE" AS "violationType"
                             , pv."TIMESTAMP" AS "violationTimestamp"
                             , pc."UUID" AS "conditionUuid"
                             , pc."SUBJECT" AS "conditionSubject"
                             , pc."OPERATOR" AS "conditionOperator"
                             , pc."VALUE" AS "conditionValue"
                             , po."UUID" AS "policyUuid"
                             , po."NAME" AS "policyName"
                             , po."VIOLATIONSTATE" AS "policyViolationState"
                             , va."SUPPRESSED" AS "analysisSuppressed"
                             , va."STATE" AS "analysisState"
                             , c."UUID" AS "componentUuid"
                             , c."GROUP" AS "componentGroup"
                             , c."NAME" AS "componentName"
                             , c."VERSION" AS "componentVersion"
                             , c."PURL" AS "componentPurl"
                             , c."MD5" AS "componentMd5"
                             , c."SHA1" AS "componentSha1"
                             , c."SHA_256" AS "componentSha256"
                             , c."SHA_512" AS "componentSha512"
                             , p."UUID" AS "projectUuid"
                             , p."NAME" AS "projectName"
                             , p."VERSION" AS "projectVersion"
                             , p."DESCRIPTION" AS "projectDescription"
                             , p."PURL" AS "projectPurl"
                             , (p."INACTIVE_SINCE" IS NULL) AS "isActive"
                             , (
                                 SELECT ARRAY_AGG(DISTINCT t."NAME")
                                   FROM "TAG" AS t
                                  INNER JOIN "PROJECTS_TAGS" AS pt
                                     ON pt."TAG_ID" = t."ID"
                                  WHERE pt."PROJECT_ID" = p."ID"
                               ) AS "projectTags"
                          FROM UNNEST(:violationIds) AS req(violation_id)
                         INNER JOIN "POLICYVIOLATION" AS pv
                            ON pv."ID" = req.violation_id
                         INNER JOIN "POLICYCONDITION" AS pc
                            ON pc."ID" = pv."POLICYCONDITION_ID"
                         INNER JOIN "POLICY" AS po
                            ON po."ID" = pc."POLICY_ID"
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = pv."COMPONENT_ID"
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = pv."PROJECT_ID"
                          LEFT JOIN "VIOLATIONANALYSIS" AS va
                            ON va."POLICYVIOLATION_ID" = pv."ID"
                         WHERE va."SUPPRESSED" IS DISTINCT FROM TRUE
                           AND va."STATE" IS DISTINCT FROM 'APPROVED'
                        """)
                .bindArray("violationIds", Long.class, violationIds)
                .map((rs, ctx) -> {
                    final Component component = componentRowMapper.map(rs, ctx);
                    final Project project = projectRowMapper.map(rs, ctx);

                    final Policy policy = Policy.newBuilder()
                            .setUuid(rs.getString("policyUuid"))
                            .setName(rs.getString("policyName"))
                            .setViolationState(rs.getString("policyViolationState"))
                            .build();

                    final PolicyCondition condition = PolicyCondition.newBuilder()
                            .setUuid(rs.getString("conditionUuid"))
                            .setSubject(rs.getString("conditionSubject"))
                            .setOperator(rs.getString("conditionOperator"))
                            .setValue(rs.getString("conditionValue"))
                            .setPolicy(policy)
                            .build();

                    final PolicyViolation violation = PolicyViolation.newBuilder()
                            .setUuid(rs.getString("violationUuid"))
                            .setType(rs.getString("violationType"))
                            .setTimestamp(RowMapperUtil.nullableTimestamp(rs, "violationTimestamp"))
                            .setCondition(condition)
                            .build();

                    return PolicyViolationSubject.newBuilder()
                            .setProject(project)
                            .setComponent(component)
                            .setPolicyViolation(violation)
                            .build();
                })
                .list();
    }

}
