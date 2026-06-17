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

import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.persistence.jdbi.mapping.NotificationRuleRowMapper;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;

import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class ScheduledNotificationDao {

    private final Handle jdbiHandle;

    public ScheduledNotificationDao(Handle jdbiHandle) {
        this.jdbiHandle = requireNonNull(jdbiHandle);
    }

    public @Nullable NotificationRule getScheduledNotificationRuleByName(String name) {
        return jdbiHandle
                .createQuery(/* language=SQL */ """
                        SELECT "ID"
                             , "UUID"
                             , "NAME"
                             , "SCOPE"
                             , "SCHEDULE_CRON"
                             , "SCHEDULE_LAST_TRIGGERED_AT"
                             , "TRIGGER_TYPE"
                             , COALESCE("SCHEDULE_SKIP_UNCHANGED", FALSE) AS "SCHEDULE_SKIP_UNCHANGED"
                             , "NOTIFY_CHILDREN"
                             , "NOTIFY_ON"
                             , "FILTER_EXPRESSION"
                          FROM "NOTIFICATIONRULE"
                         WHERE "NAME" = :name
                           AND "TRIGGER_TYPE" = 'SCHEDULE'
                        """)
                .registerRowMapper(new NotificationRuleRowMapper())
                .bind("name", name)
                .mapTo(NotificationRule.class)
                .findOne()
                .orElse(null);
    }

    public Set<String> getDueScheduledNotificationRuleNames() {
        return jdbiHandle
                .createQuery(/* language=SQL */ """
                        SELECT "NAME"
                          FROM "NOTIFICATIONRULE"
                         WHERE "ENABLED"
                           AND "TRIGGER_TYPE" = 'SCHEDULE'
                           AND "SCHEDULE_NEXT_TRIGGER_AT" <= NOW()
                        """)
                .mapTo(String.class)
                .set();
    }

    public void updateRuleLastTriggered(long ruleId, Instant lastTriggeredAt, Instant nextTriggerAt) {
        jdbiHandle
                .createUpdate(/* language=SQL */ """
                        UPDATE "NOTIFICATIONRULE"
                           SET "SCHEDULE_LAST_TRIGGERED_AT" = :lastTriggeredAt
                             , "SCHEDULE_NEXT_TRIGGER_AT" = :nextTriggerAt
                         WHERE "ID" = :ruleId
                        """)
                .bind("ruleId", ruleId)
                .bind("lastTriggeredAt", lastTriggeredAt)
                .bind("nextTriggerAt", nextTriggerAt)
                .execute();
    }

    public Set<Long> getApplicableProjectIds(long ruleId, boolean notifyChildren) {
        if (notifyChildren) {
            return jdbiHandle
                    .createQuery(/* language=SQL */ """
                            SELECT DISTINCT h."CHILD_PROJECT_ID"
                              FROM "NOTIFICATIONRULE_PROJECTS" rp
                             INNER JOIN "PROJECT_HIERARCHY" h
                                ON h."PARENT_PROJECT_ID" = rp."PROJECT_ID"
                             INNER JOIN "PROJECT" p
                                ON p."ID" = h."CHILD_PROJECT_ID"
                             WHERE rp."NOTIFICATIONRULE_ID" = :ruleId
                               AND p."INACTIVE_SINCE" IS NULL
                            """)
                    .bind("ruleId", ruleId)
                    .mapTo(Long.class)
                    .set();
        }

        return jdbiHandle
                .createQuery(/* language=SQL */ """
                        SELECT rp."PROJECT_ID"
                          FROM "NOTIFICATIONRULE_PROJECTS" rp
                         INNER JOIN "PROJECT" p
                            ON p."ID" = rp."PROJECT_ID"
                         WHERE rp."NOTIFICATIONRULE_ID" = :ruleId
                           AND p."INACTIVE_SINCE" IS NULL
                        """)
                .bind("ruleId", ruleId)
                .mapTo(Long.class)
                .set();
    }

    public record NewFinding(
            long projectId,
            long componentId,
            long vulnerabilityId,
            String analyzerIdentity,
            Instant attributedOn,
            String referenceUrl,
            String analysisState,
            boolean suppressed) {
    }

    public List<NewFinding> getNewFindingsSince(
            Collection<Long> projectIds,
            Instant sinceAttributedOn,
            Instant beforeAttributedOn) {
        return jdbiHandle
                .createQuery(/* language=SQL */ """
                        SELECT c."PROJECT_ID" AS project_id
                             , c."ID" AS component_id
                             , cv."VULNERABILITY_ID" AS vulnerability_id
                             , fa."ANALYZERIDENTITY" AS analyzer_identity
                             , fa."ATTRIBUTED_ON" AS attributed_on
                             , fa."REFERENCE_URL" AS reference_url
                             , a."STATE" AS analysis_state
                             , COALESCE(a."SUPPRESSED", FALSE) AS suppressed
                          FROM "COMPONENTS_VULNERABILITIES" cv
                         INNER JOIN "COMPONENT" c
                            ON c."ID" = cv."COMPONENT_ID"
                         INNER JOIN LATERAL (
                           SELECT *
                             FROM "FINDINGATTRIBUTION" fa
                            WHERE fa."COMPONENT_ID" = c."ID"
                              AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
                              AND fa."DELETED_AT" IS NULL
                            ORDER BY fa."ID"
                            LIMIT 1
                         ) fa ON TRUE
                          LEFT JOIN "ANALYSIS" a
                            ON a."PROJECT_ID" = c."PROJECT_ID"
                           AND a."COMPONENT_ID" = c."ID"
                           AND a."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
                         WHERE fa."ATTRIBUTED_ON" > :sinceAttributedOn
                           AND fa."ATTRIBUTED_ON" <= :beforeAttributedOn
                           AND c."PROJECT_ID" = ANY(:projectIds)
                        """)
                .bind("sinceAttributedOn", sinceAttributedOn)
                .bind("beforeAttributedOn", beforeAttributedOn)
                .bindArray("projectIds", Long.class, projectIds)
                .map(ConstructorMapper.of(NewFinding.class))
                .list();
    }

    public record NewPolicyViolation(
            UUID uuid,
            long projectId,
            long componentId,
            long policyConditionId,
            String violationType,
            Instant timestamp,
            String analysisState,
            boolean suppressed) {
    }

    public List<NewPolicyViolation> getNewPolicyViolationsSince(
            Collection<Long> projectIds,
            Instant sinceTimestamp,
            Instant beforeTimestamp) {
        return jdbiHandle
                .createQuery(/* language=SQL */ """
                        SELECT pv."UUID" AS uuid
                             , pv."PROJECT_ID" AS project_id
                             , pv."COMPONENT_ID" AS component_id
                             , pv."POLICYCONDITION_ID" AS policy_condition_id
                             , pv."TYPE" AS violation_type
                             , pv."TIMESTAMP" AS timestamp
                             , va."STATE" AS analysis_state
                             , COALESCE(va."SUPPRESSED", FALSE) AS suppressed
                          FROM "POLICYVIOLATION" pv
                          LEFT JOIN "VIOLATIONANALYSIS" va
                            ON va."POLICYVIOLATION_ID" = pv."ID"
                         WHERE pv."TIMESTAMP" > :sinceTimestamp
                           AND pv."TIMESTAMP" <= :beforeTimestamp
                           AND pv."PROJECT_ID" = ANY(:projectIds)
                        """)
                .bind("sinceTimestamp", sinceTimestamp)
                .bind("beforeTimestamp", beforeTimestamp)
                .bindArray("projectIds", Long.class, projectIds)
                .map(ConstructorMapper.of(NewPolicyViolation.class))
                .list();
    }

    public boolean hasProjectsConfigured(long ruleId) {
        return jdbiHandle
                .createQuery(/* language=SQL */ """
                        SELECT EXISTS(
                          SELECT 1
                            FROM "NOTIFICATIONRULE_PROJECTS"
                           WHERE "NOTIFICATIONRULE_ID" = :ruleId
                        )
                        """)
                .bind("ruleId", ruleId)
                .mapTo(boolean.class)
                .one();
    }

}
