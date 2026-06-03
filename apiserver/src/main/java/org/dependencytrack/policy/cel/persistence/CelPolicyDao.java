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
package org.dependencytrack.policy.cel.persistence;

import dev.cel.common.types.CelType;
import org.apache.commons.collections4.MultiValuedMap;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_PROJECT_METADATA;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_PROJECT_PROPERTY;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_VULNERABILITY;
import static org.dependencytrack.policy.cel.persistence.CelPolicyFieldMappingRegistry.COMPONENT_FIELDS;
import static org.dependencytrack.policy.cel.persistence.CelPolicyFieldMappingRegistry.COMPONENT_PROPERTY_FIELDS;
import static org.dependencytrack.policy.cel.persistence.CelPolicyFieldMappingRegistry.LICENSE_FIELDS;
import static org.dependencytrack.policy.cel.persistence.CelPolicyFieldMappingRegistry.LICENSE_GROUP_FIELDS;
import static org.dependencytrack.policy.cel.persistence.CelPolicyFieldMappingRegistry.PROJECT_FIELDS;
import static org.dependencytrack.policy.cel.persistence.CelPolicyFieldMappingRegistry.PROJECT_PROPERTY_FIELDS;
import static org.dependencytrack.policy.cel.persistence.CelPolicyFieldMappingRegistry.VULNERABILITY_FIELDS;
import static org.dependencytrack.policy.cel.persistence.CelPolicyFieldMappingRegistry.selectColumns;

public final class CelPolicyDao {

    private final Handle jdbiHandle;

    public CelPolicyDao(Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    public record ComponentWithLicenseId(
            Component component,
            @Nullable Long resolvedLicenseId) {
    }

    public Map<Long, ComponentWithLicenseId> fetchAllComponents(
            long projectId,
            Collection<String> protoFieldNames) {
        final List<String> fetchColumns = new ArrayList<>();
        fetchColumns.add("c.\"ID\" AS db_id");

        final boolean needsResolvedLicense = protoFieldNames.contains("resolved_license");
        final List<String> fieldNames = protoFieldNames.stream()
                .filter(fieldName -> !"resolved_license".equals(fieldName))
                .toList();
        fetchColumns.addAll(selectColumns(COMPONENT_FIELDS, fieldNames));

        if (needsResolvedLicense) {
            fetchColumns.add("c.\"LICENSE_ID\" AS resolved_license_id");
        }

        final boolean shouldJoinPam =
                protoFieldNames.contains("published_at")
                        || protoFieldNames.contains("latest_version");

        final var componentRowMapper = new CelPolicyComponentRowMapper();
        return jdbiHandle
                .createQuery(/* language=InjectedFreeMarker */ """
                        <#-- @ftlvariable name="fetchColumns" type="java.util.Collection<String>" -->
                        <#-- @ftlvariable name="shouldJoinPam" type="boolean" -->
                        <#-- @ftlvariable name="shouldJoinLatestVersion" type="boolean" -->
                        SELECT ${fetchColumns?join(", ")}
                          FROM "COMPONENT" AS c
                        <#if shouldJoinPam!false>
                          LEFT JOIN "PACKAGE_ARTIFACT_METADATA" AS pam
                            ON pam."PURL" = c."PURL"
                        </#if>
                        <#if shouldJoinLatestVersion!false>
                          LEFT JOIN "PACKAGE_METADATA" AS pm
                            ON pm."PURL" = pam."PACKAGE_PURL"
                        </#if>
                         WHERE c."PROJECT_ID" = :projectId
                        """)
                .define("fetchColumns", fetchColumns)
                .define("shouldJoinPam", shouldJoinPam)
                .define("shouldJoinLatestVersion", protoFieldNames.contains("latest_version"))
                .bind("projectId", projectId)
                .reduceResultSet(
                        new HashMap<>(),
                        (accumulator, rs, ctx) -> {
                            final long dbId = rs.getLong("db_id");
                            Long licenseId = needsResolvedLicense
                                    ? rs.getLong("resolved_license_id")
                                    : null;
                            if (licenseId != null && rs.wasNull()) {
                                licenseId = null;
                            }
                            accumulator.put(
                                    dbId,
                                    new ComponentWithLicenseId(
                                            componentRowMapper.map(rs, ctx),
                                            licenseId));
                            return accumulator;
                        });
    }

    public Map<Long, List<Component.Property>> fetchAllComponentProperties(
            long projectId,
            Collection<String> propertyProtoFieldNames) {
        final List<String> fetchColumns = new ArrayList<>(selectColumns(COMPONENT_PROPERTY_FIELDS, propertyProtoFieldNames));
        if (fetchColumns.isEmpty()) {
            fetchColumns.add("cp.\"ID\" AS \"_id\"");
        }

        return jdbiHandle
                .createQuery(/* language=InjectedFreeMarker */ """
                        <#-- @ftlvariable name="fetchColumns" type="java.util.Collection<String>" -->
                        SELECT cp."COMPONENT_ID" AS component_id
                             , ${fetchColumns?join(", ")}
                          FROM "COMPONENT_PROPERTY" AS cp
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = cp."COMPONENT_ID"
                         WHERE c."PROJECT_ID" = :projectId
                        """)
                .define("fetchColumns", fetchColumns)
                .bind("projectId", projectId)
                .reduceResultSet(
                        new HashMap<>(),
                        (accumulator, rs, ctx) -> {
                            final long componentId = rs.getLong("component_id");
                            final Component.Property.Builder builder = Component.Property.newBuilder();
                            maybeSet(rs, "group", ResultSet::getString, builder::setGroup);
                            maybeSet(rs, "name", ResultSet::getString, builder::setName);
                            maybeSet(rs, "value", ResultSet::getString, builder::setValue);
                            maybeSet(rs, "type", ResultSet::getString, builder::setType);
                            accumulator
                                    .computeIfAbsent(componentId, k -> new ArrayList<>())
                                    .add(builder.build());
                            return accumulator;
                        });
    }

    public Map<Long, Set<Long>> fetchAllComponentsVulnerabilities(long projectId) {
        return jdbiHandle
                .createQuery("""
                        SELECT cv."COMPONENT_ID" AS component_id
                             , cv."VULNERABILITY_ID" AS vulnerability_id
                          FROM "COMPONENTS_VULNERABILITIES" AS cv
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = cv."COMPONENT_ID"
                         WHERE c."PROJECT_ID" = :projectId
                           AND EXISTS (
                             SELECT 1
                               FROM "FINDINGATTRIBUTION" AS fa
                              WHERE fa."COMPONENT_ID" = c."ID"
                                AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
                                AND fa."DELETED_AT" IS NULL
                           )
                        """)
                .bind("projectId", projectId)
                .reduceResultSet(
                        new HashMap<>(),
                        (accumulator, rs, ctx) -> {
                            final long componentId = rs.getLong("component_id");
                            final long vulnerabilityId = rs.getLong("vulnerability_id");
                            accumulator
                                    .computeIfAbsent(componentId, k -> new HashSet<>())
                                    .add(vulnerabilityId);
                            return accumulator;
                        });
    }

    public Map<Long, License> fetchAllLicenses(
            long projectId,
            Collection<String> licenseProtoFieldNames,
            Collection<String> licenseGroupProtoFieldNames) {
        final List<String> fetchColumns = new ArrayList<>();
        fetchColumns.add("l.\"ID\" AS db_id");
        fetchColumns.addAll(selectColumns(LICENSE_FIELDS, licenseProtoFieldNames));

        if (!licenseProtoFieldNames.contains("groups")) {
            final var licenseRowMapper = new CelPolicyLicenseRowMapper();
            return jdbiHandle
                    .createQuery(/* language=InjectedFreeMarker */ """
                            <#-- @ftlvariable name="fetchColumns" type="java.util.Collection<String>" -->
                            SELECT DISTINCT ${fetchColumns?join(", ")}
                              FROM "LICENSE" AS l
                             INNER JOIN "COMPONENT" AS c
                                ON c."LICENSE_ID" = l."ID"
                             WHERE c."PROJECT_ID" = :projectId
                            """)
                    .define("fetchColumns", fetchColumns)
                    .bind("projectId", projectId)
                    .reduceResultSet(new HashMap<>(), (accumulator, rs, ctx) -> {
                        final long dbId = rs.getLong("db_id");
                        accumulator.put(dbId, licenseRowMapper.map(rs, ctx));
                        return accumulator;
                    });
        }

        final List<String> groupByColumns = Stream.concat(
                        Stream.of("l.\"ID\""),
                        LICENSE_FIELDS.stream()
                                .filter(fieldMapping -> licenseProtoFieldNames.contains(fieldMapping.protoFieldName()))
                                .map(CelPolicyFieldMappingRegistry.FieldMapping::sqlExpression))
                .toList();

        final var groupObjectColumns = new ArrayList<>(LICENSE_GROUP_FIELDS.stream()
                .filter(fieldMapping -> licenseGroupProtoFieldNames.contains(fieldMapping.protoFieldName()))
                .map(fieldMapping -> "'%s', %s".formatted(fieldMapping.protoFieldName(), fieldMapping.sqlExpression()))
                .toList());

        // Always include UUID to ensure DISTINCT produces correct cardinality,
        // even when no specific group fields are accessed.
        if (licenseGroupProtoFieldNames.stream().noneMatch("uuid"::equals)) {
            groupObjectColumns.addFirst("'uuid', lg.\"UUID\"");
        }

        fetchColumns.add("""
                CAST(
                  COALESCE(
                    JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(%s)) FILTER (WHERE lg."ID" IS NOT NULL)
                  , CAST('[]' AS JSONB)
                  ) AS TEXT
                ) AS groups_json\
                """.formatted(String.join(", ", groupObjectColumns)));

        final var licenseRowMapper = new CelPolicyLicenseRowMapper();
        return jdbiHandle
                .createQuery(/* language=InjectedFreeMarker */ """
                        <#-- @ftlvariable name="fetchColumns" type="java.util.Collection<String>" -->
                        <#-- @ftlvariable name="groupByColumns" type="java.util.Collection<String>" -->
                        SELECT DISTINCT
                          ${fetchColumns?join(", ")}
                          FROM "LICENSE" AS l
                         INNER JOIN "COMPONENT" AS c
                            ON c."LICENSE_ID" = l."ID"
                          LEFT JOIN "LICENSEGROUP_LICENSE" AS lgl
                            ON lgl."LICENSE_ID" = l."ID"
                          LEFT JOIN "LICENSEGROUP" AS lg
                            ON lg."ID" = lgl."LICENSEGROUP_ID"
                         WHERE c."PROJECT_ID" = :projectId
                         GROUP BY ${groupByColumns?join(", ")}
                        """)
                .define("fetchColumns", fetchColumns)
                .define("groupByColumns", groupByColumns)
                .bind("projectId", projectId)
                .reduceResultSet(
                        new HashMap<>(),
                        (accumulator, rs, ctx) -> {
                            final long dbId = rs.getLong("db_id");
                            accumulator.put(dbId, licenseRowMapper.map(rs, ctx));
                            return accumulator;
                        });
    }

    public Map<Long, Vulnerability> fetchAllVulnerabilities(
            long projectId,
            Collection<String> protoFieldNames) {
        final List<String> fetchColumns = new ArrayList<>();
        fetchColumns.add("v.\"ID\" AS db_id");
        fetchColumns.addAll(selectColumns(VULNERABILITY_FIELDS, protoFieldNames));

        final boolean shouldFetchEpss =
                protoFieldNames.contains("epss_score")
                        || protoFieldNames.contains("epss_percentile");

        final var vulnRowMapper = new CelPolicyVulnerabilityRowMapper();
        return jdbiHandle
                .createQuery(/* language=InjectedFreeMarker */ """
                        <#-- @ftlvariable name="fetchColumns" type="java.util.Collection<String>" -->
                        <#-- @ftlvariable name="shouldFetchEpss" type="boolean" -->
                        SELECT DISTINCT ${fetchColumns?join(", ")}
                          FROM "VULNERABILITY" AS v
                         INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                            ON cv."VULNERABILITY_ID" = v."ID"
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = cv."COMPONENT_ID"
                        <#if shouldFetchEpss!false>
                          LEFT JOIN LATERAL (
                            SELECT "CVE"
                                 , "SCORE"
                                 , "PERCENTILE"
                              FROM (
                                SELECT ee."CVE"
                                     , ee."SCORE"
                                     , ee."PERCENTILE"
                                  FROM "EPSS" AS ee
                                 WHERE v."SOURCE" = 'NVD'
                                   AND ee."CVE" = v."VULNID"
                                UNION ALL
                                SELECT ee."CVE"
                                     , ee."SCORE"
                                     , ee."PERCENTILE"
                                  FROM "VULNERABILITY_ALIAS" AS va
                                 INNER JOIN "VULNERABILITY_ALIAS" AS cve_a
                                    ON cve_a."GROUP_ID" = va."GROUP_ID"
                                   AND cve_a."SOURCE" = 'NVD'
                                 INNER JOIN "EPSS" AS ee
                                    ON ee."CVE" = cve_a."VULN_ID"
                                 WHERE v."SOURCE" != 'NVD'
                                   AND va."SOURCE" = v."SOURCE"
                                   AND va."VULN_ID" = v."VULNID"
                              ) candidates
                             ORDER BY "SCORE" DESC NULLS LAST
                                    , "PERCENTILE" DESC NULLS LAST
                                    , "CVE"
                             LIMIT 1
                          ) AS ep ON TRUE
                        </#if>
                         WHERE c."PROJECT_ID" = :projectId
                           AND EXISTS (
                             SELECT 1
                               FROM "FINDINGATTRIBUTION" AS fa
                              WHERE fa."COMPONENT_ID" = c."ID"
                                AND fa."VULNERABILITY_ID" = v."ID"
                                AND fa."DELETED_AT" IS NULL
                           )
                        """)
                .define("fetchColumns", fetchColumns)
                .define("shouldFetchEpss", shouldFetchEpss)
                .bind("projectId", projectId)
                .reduceResultSet(
                        new HashMap<>(),
                        (accumulator, rs, ctx) -> {
                            final long dbId = rs.getLong("db_id");
                            accumulator.put(dbId, vulnRowMapper.map(rs, ctx));
                            return accumulator;
                        });
    }

    public boolean isDirectDependency(Component component) {
        return jdbiHandle
                .createQuery("""
                        SELECT COALESCE((
                           SELECT c."DIRECT_DEPENDENCY"
                           FROM "COMPONENT" c
                           WHERE c."UUID" = CAST(:uuid AS UUID)
                        ), FALSE)
                        """)
                .bind("uuid", component.getUuid())
                .mapTo(Boolean.class)
                .one();
    }

    public List<Policy> getApplicablePolicies(long projectId) {
        return jdbiHandle
                .createQuery("""
                        SELECT p."ID" AS policy_id
                             , p."UUID" AS policy_uuid
                             , p."NAME" AS policy_name
                             , p."OPERATOR" AS policy_operator
                             , p."VIOLATIONSTATE" AS policy_violation_state
                             , pc."ID" AS condition_id
                             , pc."UUID" AS condition_uuid
                             , pc."OPERATOR" AS condition_operator
                             , pc."SUBJECT" AS condition_subject
                             , pc."VALUE" AS condition_value
                             , pc."VIOLATIONTYPE" AS condition_violation_type
                          FROM "POLICY" AS p
                         INNER JOIN "POLICYCONDITION" AS pc
                            ON pc."POLICY_ID" = p."ID"
                         WHERE p."ID" IN (
                           -- "Global" policies without restrictions.
                           SELECT p2."ID"
                             FROM "POLICY" AS p2
                            WHERE NOT EXISTS (SELECT 1 FROM "POLICY_PROJECTS" WHERE "POLICY_ID" = p2."ID")
                              AND NOT EXISTS (SELECT 1 FROM "POLICY_TAGS" WHERE "POLICY_ID" = p2."ID")
                           UNION
                           -- Policies restricted to the project, or a parent of the project.
                           SELECT pp."POLICY_ID"
                             FROM "POLICY_PROJECTS" AS pp
                            INNER JOIN "POLICY" AS p3
                               ON p3."ID" = pp."POLICY_ID"
                            INNER JOIN "PROJECT_HIERARCHY" AS ph
                               ON ph."PARENT_PROJECT_ID" = pp."PROJECT_ID"
                            WHERE ph."CHILD_PROJECT_ID" = :projectId
                              AND (ph."DEPTH" = 0 OR p3."INCLUDE_CHILDREN")
                           UNION
                           -- Policies restricted tags shared with the project.
                           SELECT pt."POLICY_ID"
                             FROM "POLICY_TAGS" AS pt
                            INNER JOIN "PROJECTS_TAGS" AS prt
                               ON prt."TAG_ID" = pt."TAG_ID"
                            WHERE prt."PROJECT_ID" = :projectId
                         )
                         ORDER BY p."ID"
                                , pc."ID"
                        """)
                .bind("projectId", projectId)
                .reduceResultSet(
                        new LinkedHashMap<Long, Policy>(),
                        (accumulator, rs, ctx) -> {
                            final long policyId = rs.getLong("policy_id");

                            Policy policy = accumulator.get(policyId);
                            if (policy == null) {
                                policy = new Policy();
                                policy.setId(policyId);
                                policy.setUuid(rs.getObject("policy_uuid", UUID.class));
                                policy.setName(rs.getString("policy_name"));
                                policy.setOperator(Policy.Operator.valueOf(rs.getString("policy_operator")));
                                policy.setViolationState(Policy.ViolationState.valueOf(rs.getString("policy_violation_state")));
                                policy.setPolicyConditions(new ArrayList<>());
                                accumulator.put(policyId, policy);
                            }

                            final var condition = new PolicyCondition();
                            condition.setId(rs.getLong("condition_id"));
                            condition.setUuid(rs.getObject("condition_uuid", UUID.class));
                            condition.setOperator(PolicyCondition.Operator.valueOf(rs.getString("condition_operator")));
                            condition.setSubject(PolicyCondition.Subject.valueOf(rs.getString("condition_subject")));
                            condition.setValue(rs.getString("condition_value"));
                            final String violationType = rs.getString("condition_violation_type");
                            if (violationType != null) {
                                condition.setViolationType(PolicyViolation.Type.valueOf(violationType));
                            }
                            condition.setPolicy(policy);

                            policy.getPolicyConditions().add(condition);

                            return accumulator;
                        })
                .values()
                .stream()
                .toList();
    }

    public Set<Long> reconcileViolations(
            long projectId,
            MultiValuedMap<Long, PolicyViolation> reportedViolationsByComponentId) {
        if (reportedViolationsByComponentId.isEmpty()) {
            jdbiHandle
                    .createUpdate("""
                            DELETE FROM "POLICYVIOLATION"
                             WHERE "ID" IN (
                               SELECT "ID"
                                 FROM "POLICYVIOLATION"
                                WHERE "PROJECT_ID" = :projectId
                                ORDER BY "ID"
                                  FOR UPDATE
                             )
                            """)
                    .bind("projectId", projectId)
                    .execute();
            return Set.of();
        }

        final int size = reportedViolationsByComponentId.size();
        final var timestamps = new Timestamp[size];
        final var componentIds = new Long[size];
        final var projIds = new Long[size];
        final var condIds = new Long[size];
        final var types = new String[size];

        int i = 0;
        for (final var entry : reportedViolationsByComponentId.entries()) {
            timestamps[i] = new Timestamp(entry.getValue().getTimestamp().getTime());
            componentIds[i] = entry.getKey();
            projIds[i] = projectId;
            condIds[i] = entry.getValue().getPolicyCondition().getId();
            types[i] = entry.getValue().getType().name();
            i++;
        }

        return jdbiHandle
                .createQuery("""
                        WITH created AS (
                          INSERT INTO "POLICYVIOLATION" (
                            "UUID"
                          , "TIMESTAMP"
                          , "COMPONENT_ID"
                          , "PROJECT_ID"
                          , "POLICYCONDITION_ID"
                          , "TYPE"
                          )
                          SELECT GEN_RANDOM_UUID()
                               , t.*
                            FROM UNNEST(:timestamps, :componentIds, :projectIds, :policyConditionIds, :types)
                              AS t("TIMESTAMP", "COMPONENT_ID", "PROJECT_ID", "POLICYCONDITION_ID", "TYPE")
                           ORDER BY t."PROJECT_ID"
                                  , t."COMPONENT_ID"
                                  , t."POLICYCONDITION_ID"
                          ON CONFLICT DO NOTHING
                          RETURNING "ID"
                        ),
                        deleted AS (
                          DELETE FROM "POLICYVIOLATION"
                           WHERE "ID" IN (
                             SELECT "ID"
                               FROM "POLICYVIOLATION"
                              WHERE "PROJECT_ID" = :projectId
                                AND ("COMPONENT_ID", "POLICYCONDITION_ID") NOT IN (
                                  SELECT * FROM UNNEST(:componentIds, :policyConditionIds)
                                )
                              ORDER BY "ID"
                                FOR UPDATE
                           )
                        )
                        SELECT "ID" FROM created
                        """)
                .bind("timestamps", timestamps)
                .bind("componentIds", componentIds)
                .bind("projectIds", projIds)
                .bind("policyConditionIds", condIds)
                .bind("types", types)
                .bind("projectId", projectId)
                .mapTo(Long.class)
                .set();
    }

    public Project loadRequiredFields(long projectId, MultiValuedMap<CelType, String> requirements) {
        final Collection<String> projectRequirements = requirements.get(TYPE_PROJECT);
        if (projectRequirements.isEmpty()) {
            return Project.getDefaultInstance();
        }

        final var allProjectFieldNames = new ArrayList<>(projectRequirements);
        final boolean needsMetadataTools = projectRequirements.contains("metadata")
                && requirements.containsKey(TYPE_PROJECT_METADATA)
                && requirements.get(TYPE_PROJECT_METADATA).contains("tools");
        final boolean needsBomGenerated = projectRequirements.contains("metadata")
                && requirements.containsKey(TYPE_PROJECT_METADATA)
                && requirements.get(TYPE_PROJECT_METADATA).contains("bom_generated");

        if (needsMetadataTools) {
            allProjectFieldNames.add("metadata_tools");
        }
        if (needsBomGenerated) {
            allProjectFieldNames.add("bom_generated");
        }
        if (projectRequirements.contains("is_active")) {
            allProjectFieldNames.add("inactive_since");
        }

        final List<String> fetchColumns = new ArrayList<>(selectColumns(PROJECT_FIELDS, allProjectFieldNames));

        final var propertyColumns = new ArrayList<String>();
        final boolean needsProperties = projectRequirements.contains("properties");
        if (needsProperties) {
            fetchColumns.add("properties");
            if (requirements.containsKey(TYPE_PROJECT_PROPERTY)) {
                PROJECT_PROPERTY_FIELDS.stream()
                        .filter(f -> requirements.get(TYPE_PROJECT_PROPERTY).contains(f.protoFieldName()))
                        .map(f -> "'%s', %s".formatted(f.protoFieldName(), f.sqlExpression()))
                        .forEach(propertyColumns::add);
            }

            // Always include ID to ensure DISTINCT produces correct cardinality,
            // even when no specific property fields are accessed.
            if (propertyColumns.isEmpty()) {
                propertyColumns.add("'_id', pp.\"ID\"");
            }
        }

        final boolean needsTags = projectRequirements.contains("tags");
        if (needsTags) {
            fetchColumns.add("tags");
        }

        final Project project = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                        <#-- @ftlvariable name="fetchColumns" type="java.util.Collection<String>" -->
                        <#-- @ftlvariable name="needsMetadataTools" type="boolean" -->
                        <#-- @ftlvariable name="needsBomGenerated" type="boolean" -->
                        <#-- @ftlvariable name="needsProperties" type="boolean" -->
                        <#-- @ftlvariable name="propertyColumns" type="java.util.Collection<String>" -->
                        <#-- @ftlvariable name="needsTags" type="boolean" -->
                        SELECT ${fetchColumns?join(", ")}
                          FROM "PROJECT" AS p
                        <#if needsMetadataTools!false>
                         INNER JOIN "PROJECT_METADATA" AS pm
                            ON pm."PROJECT_ID" = p."ID"
                        </#if>
                        <#if needsBomGenerated!false>
                         INNER JOIN "BOM" AS b
                            ON b."PROJECT_ID" = p."ID"
                        </#if>
                        <#if needsProperties!false>
                          LEFT JOIN LATERAL (
                            SELECT CAST(JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(${propertyColumns?join(", ")})) AS TEXT) AS properties
                              FROM "PROJECT_PROPERTY" AS pp
                             WHERE pp."PROJECT_ID" = p."ID"
                          ) AS properties_sub ON TRUE
                        </#if>
                        <#if needsTags!false>
                          LEFT JOIN LATERAL (
                            SELECT ARRAY_AGG(DISTINCT t."NAME") AS tags
                              FROM "TAG" AS t
                             INNER JOIN "PROJECTS_TAGS" AS pt
                                ON pt."TAG_ID" = t."ID"
                             WHERE pt."PROJECT_ID" = p."ID"
                          ) AS tags_sub ON TRUE
                        </#if>
                         WHERE p."ID" = :id
                        """)
                .define("fetchColumns", fetchColumns)
                .define("needsMetadataTools", needsMetadataTools)
                .define("needsBomGenerated", needsBomGenerated)
                .define("needsProperties", needsProperties)
                .define("propertyColumns", propertyColumns)
                .define("needsTags", needsTags)
                .bind("id", projectId)
                .map(new CelPolicyProjectRowMapper())
                .findOne()
                .orElse(null);

        if (project == null) {
            throw new NoSuchElementException();
        }

        return project;
    }

    public Map<Long, Component> loadRequiredComponentFields(
            Collection<Long> componentIds,
            MultiValuedMap<CelType, String> requirements) {
        if (componentIds.isEmpty()) {
            return Map.of();
        }

        final Collection<String> componentRequirements = requirements.get(TYPE_COMPONENT);
        if (componentRequirements.isEmpty()) {
            final var result = new HashMap<Long, Component>();
            for (long componentId : componentIds) {
                result.put(componentId, Component.getDefaultInstance());
            }
            return result;
        }

        final List<String> fetchColumns = new ArrayList<>(selectColumns(COMPONENT_FIELDS, componentRequirements));

        final boolean needsLatestVersion = componentRequirements.contains("latest_version");
        final boolean needsPublishedAt = componentRequirements.contains("published_at");
        final boolean needsPam = needsPublishedAt || needsLatestVersion;

        final var componentRowMapper = new CelPolicyComponentRowMapper();
        return jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                        <#-- @ftlvariable name="fetchColumns" type="java.util.Collection<String>" -->
                        <#-- @ftlvariable name="needsPam" type="boolean" -->
                        <#-- @ftlvariable name="needsLatestVersion" type="boolean" -->
                        SELECT c."ID" AS db_id
                        <#if fetchColumns?size gt 0>
                             , ${fetchColumns?join(", ")}
                        </#if>
                          FROM "COMPONENT" AS c
                        <#if needsPam!false>
                          LEFT JOIN "PACKAGE_ARTIFACT_METADATA" AS pam
                            ON pam."PURL" = c."PURL"
                        </#if>
                        <#if needsLatestVersion!false>
                          LEFT JOIN "PACKAGE_METADATA" AS pm
                            ON pm."PURL" = pam."PACKAGE_PURL"
                        </#if>
                         WHERE c."ID" = ANY(:ids)
                        """)
                .define("fetchColumns", fetchColumns)
                .define("needsPam", needsPam)
                .define("needsLatestVersion", needsLatestVersion)
                .bindArray("ids", Long.class, componentIds)
                .reduceResultSet(new HashMap<>(), (accumulator, rs, ctx) -> {
                    final long dbId = rs.getLong("db_id");
                    accumulator.put(dbId, componentRowMapper.map(rs, ctx));
                    return accumulator;
                });
    }

    public Map<Long, Vulnerability> loadRequiredVulnerabilityFields(
            Collection<Long> vulnIds,
            MultiValuedMap<CelType, String> requirements) {
        if (vulnIds.isEmpty()) {
            return Map.of();
        }

        final Collection<String> vulnRequirements = requirements.get(TYPE_VULNERABILITY);
        if (vulnRequirements.isEmpty()) {
            final var result = new HashMap<Long, Vulnerability>();
            for (long vulnId : vulnIds) {
                result.put(vulnId, Vulnerability.getDefaultInstance());
            }
            return result;
        }

        final List<String> fetchColumns = new ArrayList<>(selectColumns(VULNERABILITY_FIELDS, vulnRequirements));

        final boolean needsEpss = vulnRequirements.contains("epss_score")
                || vulnRequirements.contains("epss_percentile");

        final var vulnRowMapper = new CelPolicyVulnerabilityRowMapper();

        return jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                        <#-- @ftlvariable name="fetchColumns" type="java.util.Collection<String>" -->
                        <#-- @ftlvariable name="needsEpss" type="boolean" -->
                        SELECT v."ID" AS db_id
                        <#if fetchColumns?size gt 0>
                             , ${fetchColumns?join(", ")}
                        </#if>
                          FROM "VULNERABILITY" AS v
                        <#if needsEpss!false>
                          LEFT JOIN LATERAL (
                            SELECT "CVE"
                                 , "SCORE"
                                 , "PERCENTILE"
                              FROM (
                                SELECT ee."CVE"
                                     , ee."SCORE"
                                     , ee."PERCENTILE"
                                  FROM "EPSS" AS ee
                                 WHERE v."SOURCE" = 'NVD'
                                   AND ee."CVE" = v."VULNID"
                                UNION ALL
                                SELECT ee."CVE"
                                     , ee."SCORE"
                                     , ee."PERCENTILE"
                                  FROM "VULNERABILITY_ALIAS" AS va
                                 INNER JOIN "VULNERABILITY_ALIAS" AS cve_a
                                    ON cve_a."GROUP_ID" = va."GROUP_ID"
                                   AND cve_a."SOURCE" = 'NVD'
                                 INNER JOIN "EPSS" AS ee
                                    ON ee."CVE" = cve_a."VULN_ID"
                                 WHERE v."SOURCE" != 'NVD'
                                   AND va."SOURCE" = v."SOURCE"
                                   AND va."VULN_ID" = v."VULNID"
                              ) candidates
                             ORDER BY "SCORE" DESC NULLS LAST
                                    , "PERCENTILE" DESC NULLS LAST
                                    , "CVE"
                             LIMIT 1
                          ) AS ep ON TRUE
                        </#if>
                         WHERE v."ID" = ANY(:ids)
                        """)
                .define("fetchColumns", fetchColumns)
                .define("needsEpss", needsEpss)
                .bindArray("ids", Long.class, vulnIds)
                .reduceResultSet(
                        new HashMap<>(),
                        (accumulator, rs, ctx) -> {
                            final long dbId = rs.getLong("db_id");
                            accumulator.put(dbId, vulnRowMapper.map(rs, ctx));
                            return accumulator;
                        });
    }

}
