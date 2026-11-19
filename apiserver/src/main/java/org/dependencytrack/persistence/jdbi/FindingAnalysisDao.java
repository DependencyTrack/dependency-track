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

import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.model.Severity;
import org.dependencytrack.notification.GetProjectAuditChangeNotificationSubjectQuery;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.NotificationSubjectDao;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.util.AnalysisCommentFormatter.AnalysisCommentField;
import org.jdbi.v3.core.mapper.reflect.ColumnName;
import org.jdbi.v3.json.Json;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.BindMethods;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.notification.api.NotificationFactory.createVulnerabilityAnalysisDecisionChangeNotification;
import static org.dependencytrack.support.jdbi.binding.Bindings.columnValues;
import static org.dependencytrack.util.AnalysisCommentFormatter.formatComment;

/// @since 5.3.0
@NullMarked
@RegisterConstructorMapper(FindingAnalysisDao.Analysis.class)
@RegisterConstructorMapper(FindingAnalysisDao.AnalysisTrail.class)
public interface FindingAnalysisDao extends SqlObject {

    record Analysis(
            long id,
            long componentId,
            @ColumnName("VULNERABILITY_ID") long vulnDbId,
            @Nullable Long vulnerabilityPolicyId,
            AnalysisState state,
            @Nullable AnalysisJustification justification,
            @Nullable AnalysisResponse response,
            @Nullable String details,
            boolean suppressed,
            @Nullable Severity severity,
            @Nullable String cvssV2Vector,
            @Nullable BigDecimal cvssV2Score,
            @Nullable String cvssV3Vector,
            @Nullable BigDecimal cvssV3Score,
            @Nullable String cvssV4Vector,
            @Nullable BigDecimal cvssV4Score,
            @Nullable String owaspVector,
            @Nullable BigDecimal owaspScore) {}

    record UpsertAnalysisCommand(
            long projectId,
            long componentId,
            long vulnDbId,
            @Nullable String vulnPolicyName,
            AnalysisState state,
            AnalysisJustification justification,
            AnalysisResponse response,
            @Nullable String details,
            boolean suppressed,
            @Nullable Severity severity,
            @Nullable String cvssV2Vector,
            @Nullable Double cvssV2Score,
            @Nullable String cvssV3Vector,
            @Nullable Double cvssV3Score,
            @Nullable String cvssV4Vector,
            @Nullable Double cvssV4Score,
            @Nullable String owaspVector,
            @Nullable Double owaspScore) {}

    record CreateCommentCommand(long analysisId, @Nullable String commenter, String comment) {}

    record AnalysisTrail(
            AnalysisState state,
            @Nullable AnalysisJustification justification,
            @Nullable AnalysisResponse response,
            @Nullable String details,
            boolean suppressed,
            @Nullable Severity severity,
            @Nullable String cvssV2Vector,
            @Nullable BigDecimal cvssV2Score,
            @Nullable String cvssV3Vector,
            @Nullable BigDecimal cvssV3Score,
            @Nullable String cvssV4Vector,
            @Nullable BigDecimal cvssV4Score,
            @Nullable String owaspVector,
            @Nullable BigDecimal owaspScore,
            @Json List<Comment> comments) {

        public record Comment(
                Instant timestamp, String comment, @Nullable String commenter) {}
    }

    @SqlUpdate("""
        INSERT INTO "ANALYSIS" (
          "PROJECT_ID"
        , "COMPONENT_ID"
        , "VULNERABILITY_ID"
        , "STATE"
        , "JUSTIFICATION"
        , "RESPONSE"
        , "SUPPRESSED"
        )
        SELECT "PROJECT_ID"
             , "ID"
             , :vulnDbId
             , 'NOT_SET'
             , 'NOT_SET'
             , 'NOT_SET'
             , FALSE
          FROM "COMPONENT"
         WHERE "ID" = :componentId
        ON CONFLICT ("PROJECT_ID", "COMPONENT_ID", "VULNERABILITY_ID") DO NOTHING
        RETURNING "ID"
                , "COMPONENT_ID"
                , "VULNERABILITY_ID"
                , "VULNERABILITY_POLICY_ID"
                , "STATE"
                , "JUSTIFICATION"
                , "RESPONSE"
                , "DETAILS"
                , "SUPPRESSED"
                , "SEVERITY"
                , "CVSSV2VECTOR"
                , "CVSSV2SCORE"
                , "CVSSV3VECTOR"
                , "CVSSV3SCORE"
                , "CVSSV4VECTOR"
                , "CVSSV4SCORE"
                , "OWASPVECTOR"
                , "OWASPSCORE"
        """)
    @GetGeneratedKeys
    @Nullable
    Analysis createAnalysisIfMissing(@Bind long componentId, @Bind long vulnDbId);

    @SqlQuery("""
        SELECT "ID"
             , "COMPONENT_ID"
             , "VULNERABILITY_ID"
             , "VULNERABILITY_POLICY_ID"
             , "STATE"
             , "JUSTIFICATION"
             , "RESPONSE"
             , "DETAILS"
             , "SUPPRESSED"
             , "SEVERITY"
             , "CVSSV2VECTOR"
             , "CVSSV2SCORE"
             , "CVSSV3VECTOR"
             , "CVSSV3SCORE"
             , "CVSSV4VECTOR"
             , "CVSSV4SCORE"
             , "OWASPVECTOR"
             , "OWASPSCORE"
          FROM "ANALYSIS"
         WHERE "COMPONENT_ID" = :componentId
           AND "VULNERABILITY_ID" = :vulnDbId
           FOR UPDATE
        """)
    @Nullable
    Analysis getAndLockAnalysis(@Bind long componentId, @Bind long vulnDbId);

    @SqlUpdate("""
        UPDATE "ANALYSIS"
           SET "STATE" = :state
             , "JUSTIFICATION" = :justification
             , "RESPONSE" = :response
             , "DETAILS" = :details
             , "SUPPRESSED" = :suppressed
             , "OWASPVECTOR" = :owaspVector
             , "OWASPSCORE" = :owaspScore
         WHERE "ID" = :id
        """)
    void updateAnalysis(@BindMethods Analysis analysis);

    default int createComments(List<CreateCommentCommand> commands) {
        if (commands.isEmpty()) {
            return 0;
        }

        return getHandle()
                .createUpdate("""
                    INSERT INTO "ANALYSISCOMMENT" ("ANALYSIS_ID", "COMMENTER", "COMMENT", "TIMESTAMP")
                    SELECT t.analysis_id
                         , t.commenter
                         , t.comment
                         , STATEMENT_TIMESTAMP()
                      FROM UNNEST(:analysisIds, :commenters, :comments)
                           WITH ORDINALITY AS t(analysis_id, commenter, comment, ordinality)
                     ORDER BY t.ordinality
                    """)
                .bindArray("analysisIds", Long.class, columnValues(commands, CreateCommentCommand::analysisId))
                .bindArray("commenters", String.class, columnValues(commands, CreateCommentCommand::commenter))
                .bindArray("comments", String.class, columnValues(commands, CreateCommentCommand::comment))
                .execute();
    }

    default long makeAnalysis(MakeAnalysisCommand command) {
        if (!getHandle().isInTransaction()) {
            throw new IllegalStateException("Must be called within a transaction");
        }

        Analysis current = getAndLockAnalysis(command.componentId(), command.vulnDbId());
        if (current == null) {
            current = createAnalysisIfMissing(command.componentId(), command.vulnDbId());
        }
        if (current == null) {
            // A concurrent transaction created it after the first lookup's snapshot was taken.
            current = getAndLockAnalysis(command.componentId(), command.vulnDbId());
        }
        if (current == null) {
            throw new NoSuchElementException("Component %d does not exist".formatted(command.componentId()));
        }

        final boolean owaspScoreChanged = command.owaspScore() != null
                && (current.owaspScore() == null || command.owaspScore().compareTo(current.owaspScore()) != 0);
        final var updated = new Analysis(
                current.id(),
                current.componentId(),
                current.vulnDbId(),
                current.vulnerabilityPolicyId(),
                command.state() != null ? command.state() : current.state(),
                command.justification() != null ? command.justification() : current.justification(),
                command.response() != null ? command.response() : current.response(),
                command.details() != null ? command.details() : current.details(),
                command.suppress() != null ? command.suppress() : current.suppressed(),
                current.severity(),
                current.cvssV2Vector(),
                current.cvssV2Score(),
                current.cvssV3Vector(),
                current.cvssV3Score(),
                current.cvssV4Vector(),
                current.cvssV4Score(),
                command.owaspVector() != null ? command.owaspVector() : current.owaspVector(),
                owaspScoreChanged ? command.owaspScore() : current.owaspScore());

        final var comments = new ArrayList<String>();
        if (updated.state() != current.state()) {
            comments.add(formatComment(AnalysisCommentField.STATE, current.state(), updated.state()));
        }
        if (updated.justification() != current.justification()) {
            comments.add(formatComment(
                    AnalysisCommentField.JUSTIFICATION, current.justification(), updated.justification()));
        }
        if (updated.response() != current.response()) {
            comments.add(formatComment(AnalysisCommentField.RESPONSE, current.response(), updated.response()));
        }
        if (!Objects.equals(updated.details(), current.details())) {
            comments.add(formatComment(AnalysisCommentField.DETAILS, current.details(), updated.details()));
        }
        if (updated.suppressed() != current.suppressed()) {
            comments.add(formatComment(AnalysisCommentField.SUPPRESSED, current.suppressed(), updated.suppressed()));
        }
        if (!Objects.equals(updated.owaspVector(), current.owaspVector())) {
            comments.add(
                    formatComment(AnalysisCommentField.OWASP_VECTOR, current.owaspVector(), updated.owaspVector()));
        }
        if (owaspScoreChanged) {
            comments.add(formatComment(AnalysisCommentField.OWASP_SCORE, current.owaspScore(), updated.owaspScore()));
        }

        if (!updated.equals(current)) {
            updateAnalysis(updated);
        }

        if (command.options().contains(MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL)) {
            comments.clear();
        }
        if (command.comment() != null) {
            comments.add(command.comment());
        }
        if (!comments.isEmpty()) {
            final long analysisId = current.id();
            createComments(comments.stream()
                    .map(comment -> new CreateCommentCommand(analysisId, command.commenter(), comment))
                    .toList());
        }

        final boolean stateChanged = updated.state() != current.state();
        final boolean suppressionChanged = updated.suppressed() != current.suppressed();
        if (!command.options().contains(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)
                && (stateChanged || suppressionChanged)) {
            final List<Notification> notifications = getHandle()
                    .attach(NotificationSubjectDao.class)
                    .getForProjectAuditChanges(List.of(new GetProjectAuditChangeNotificationSubjectQuery(
                            command.componentId(), command.vulnDbId(), updated.state(), updated.suppressed())))
                    .stream()
                    .map(subject -> createVulnerabilityAnalysisDecisionChangeNotification(
                            subject.getProject(),
                            subject.getComponent(),
                            subject.getVulnerability(),
                            subject.getAnalysis(),
                            stateChanged,
                            suppressionChanged))
                    .toList();
            new JdbiNotificationEmitter(getHandle()).emitAll(notifications);
        }

        return current.id();
    }

    default Map<FindingKey, Long> upsertAnalyses(List<UpsertAnalysisCommand> commands) {
        if (commands.isEmpty()) {
            return Map.of();
        }

        return getHandle()
                .createUpdate("""
                    WITH cte_vuln_policy AS (
                      SELECT "ID"
                           , "NAME"
                        FROM "VULNERABILITY_POLICY"
                       WHERE "NAME" = ANY(:vulnPolicyNames)
                    )
                    INSERT INTO "ANALYSIS" AS a (
                      "PROJECT_ID"
                    , "COMPONENT_ID"
                    , "VULNERABILITY_ID"
                    , "VULNERABILITY_POLICY_ID"
                    , "STATE"
                    , "JUSTIFICATION"
                    , "RESPONSE"
                    , "DETAILS"
                    , "SUPPRESSED"
                    , "SEVERITY"
                    , "CVSSV2VECTOR"
                    , "CVSSV2SCORE"
                    , "CVSSV3VECTOR"
                    , "CVSSV3SCORE"
                    , "CVSSV4VECTOR"
                    , "CVSSV4SCORE"
                    , "OWASPVECTOR"
                    , "OWASPSCORE"
                    )
                    SELECT project_id
                         , component_id
                         , vulnerability_id
                         , vp."ID"
                         , state
                         , justification
                         , response
                         , details
                         , suppressed
                         , severity
                         , cvss_v2_vector
                         , cvss_v2_score
                         , cvss_v3_vector
                         , cvss_v3_score
                         , cvss_v4_vector
                         , cvss_v4_score
                         , owasp_vector
                         , owasp_score
                      FROM UNNEST (
                        :projectIds
                      , :componentIds
                      , :vulnDbIds
                      , :vulnPolicyNames
                      , :states
                      , :justifications
                      , :responses
                      , :details
                      , :suppressedArray
                      , CAST(:severities AS severity[])
                      , :cvssV2Vectors
                      , :cvssV2Scores
                      , :cvssV3Vectors
                      , :cvssV3Scores
                      , :cvssV4Vectors
                      , :cvssV4Scores
                      , :owaspVectors
                      , :owaspScores
                      ) AS t (
                        project_id
                      , component_id
                      , vulnerability_id
                      , vuln_policy_name
                      , state
                      , justification
                      , response
                      , details
                      , suppressed
                      , severity
                      , cvss_v2_vector
                      , cvss_v2_score
                      , cvss_v3_vector
                      , cvss_v3_score
                      , cvss_v4_vector
                      , cvss_v4_score
                      , owasp_vector
                      , owasp_score
                      )
                      LEFT JOIN cte_vuln_policy AS vp
                        ON vp."NAME" = t.vuln_policy_name
                     ORDER BY project_id
                            , component_id
                            , vulnerability_id
                    ON CONFLICT ("PROJECT_ID", "COMPONENT_ID", "VULNERABILITY_ID") DO UPDATE
                    SET "VULNERABILITY_POLICY_ID" = EXCLUDED."VULNERABILITY_POLICY_ID"
                      , "STATE" = EXCLUDED."STATE"
                      , "JUSTIFICATION" = EXCLUDED."JUSTIFICATION"
                      , "RESPONSE" = EXCLUDED."RESPONSE"
                      , "DETAILS" = EXCLUDED."DETAILS"
                      , "SUPPRESSED" = EXCLUDED."SUPPRESSED"
                      , "SEVERITY" = EXCLUDED."SEVERITY"
                      , "CVSSV2VECTOR" = EXCLUDED."CVSSV2VECTOR"
                      , "CVSSV2SCORE" = EXCLUDED."CVSSV2SCORE"
                      , "CVSSV3VECTOR" = EXCLUDED."CVSSV3VECTOR"
                      , "CVSSV3SCORE" = EXCLUDED."CVSSV3SCORE"
                      , "CVSSV4VECTOR" = EXCLUDED."CVSSV4VECTOR"
                      , "CVSSV4SCORE" = EXCLUDED."CVSSV4SCORE"
                      , "OWASPVECTOR" = EXCLUDED."OWASPVECTOR"
                      , "OWASPSCORE" = EXCLUDED."OWASPSCORE"
                    WHERE (
                        a."VULNERABILITY_POLICY_ID"
                      , a."STATE"
                      , a."JUSTIFICATION"
                      , a."RESPONSE"
                      , a."DETAILS"
                      , a."SUPPRESSED"
                      , a."SEVERITY"
                      , a."CVSSV2VECTOR"
                      , a."CVSSV2SCORE"
                      , a."CVSSV3VECTOR"
                      , a."CVSSV3SCORE"
                      , a."CVSSV4VECTOR"
                      , a."CVSSV4SCORE"
                      , a."OWASPVECTOR"
                      , a."OWASPSCORE"
                      ) IS DISTINCT FROM (
                        EXCLUDED."VULNERABILITY_POLICY_ID"
                      , EXCLUDED."STATE"
                      , EXCLUDED."JUSTIFICATION"
                      , EXCLUDED."RESPONSE"
                      , EXCLUDED."DETAILS"
                      , EXCLUDED."SUPPRESSED"
                      , EXCLUDED."SEVERITY"
                      , EXCLUDED."CVSSV2VECTOR"
                      , EXCLUDED."CVSSV2SCORE"
                      , EXCLUDED."CVSSV3VECTOR"
                      , EXCLUDED."CVSSV3SCORE"
                      , EXCLUDED."CVSSV4VECTOR"
                      , EXCLUDED."CVSSV4SCORE"
                      , EXCLUDED."OWASPVECTOR"
                      , EXCLUDED."OWASPSCORE"
                      )
                    RETURNING "ID"
                            , "COMPONENT_ID"
                            , "VULNERABILITY_ID"
                    """)
                .bindArray("projectIds", Long.class, columnValues(commands, UpsertAnalysisCommand::projectId))
                .bindArray("componentIds", Long.class, columnValues(commands, UpsertAnalysisCommand::componentId))
                .bindArray("vulnDbIds", Long.class, columnValues(commands, UpsertAnalysisCommand::vulnDbId))
                .bindArray(
                        "vulnPolicyNames", String.class, columnValues(commands, UpsertAnalysisCommand::vulnPolicyName))
                .bindArray(
                        "states",
                        String.class,
                        columnValues(commands, command -> command.state().name()))
                .bindArray(
                        "justifications",
                        String.class,
                        columnValues(
                                commands, command -> command.justification().name()))
                .bindArray(
                        "responses",
                        String.class,
                        columnValues(commands, command -> command.response().name()))
                .bindArray("details", String.class, columnValues(commands, UpsertAnalysisCommand::details))
                .bindArray("suppressedArray", Boolean.class, columnValues(commands, UpsertAnalysisCommand::suppressed))
                .bindArray(
                        "severities",
                        String.class,
                        columnValues(
                                commands,
                                command -> command.severity() != null
                                        ? command.severity().name()
                                        : null))
                .bindArray("cvssV2Vectors", String.class, columnValues(commands, UpsertAnalysisCommand::cvssV2Vector))
                .bindArray("cvssV2Scores", Double.class, columnValues(commands, UpsertAnalysisCommand::cvssV2Score))
                .bindArray("cvssV3Vectors", String.class, columnValues(commands, UpsertAnalysisCommand::cvssV3Vector))
                .bindArray("cvssV3Scores", Double.class, columnValues(commands, UpsertAnalysisCommand::cvssV3Score))
                .bindArray("cvssV4Vectors", String.class, columnValues(commands, UpsertAnalysisCommand::cvssV4Vector))
                .bindArray("cvssV4Scores", Double.class, columnValues(commands, UpsertAnalysisCommand::cvssV4Score))
                .bindArray("owaspVectors", String.class, columnValues(commands, UpsertAnalysisCommand::owaspVector))
                .bindArray("owaspScores", Double.class, columnValues(commands, UpsertAnalysisCommand::owaspScore))
                .executeAndReturnGeneratedKeys()
                .map((rs, _) -> Map.entry(
                        new FindingKey(rs.getLong("COMPONENT_ID"), rs.getLong("VULNERABILITY_ID")), rs.getLong("ID")))
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @SqlQuery("""
        SELECT a."STATE"
             , a."JUSTIFICATION"
             , a."RESPONSE"
             , a."DETAILS"
             , a."SUPPRESSED"
             , a."SEVERITY"
             , a."CVSSV2VECTOR"
             , a."CVSSV2SCORE"
             , a."CVSSV3VECTOR"
             , a."CVSSV3SCORE"
             , a."CVSSV4VECTOR"
             , a."CVSSV4SCORE"
             , a."OWASPVECTOR"
             , a."OWASPSCORE"
             , (SELECT COALESCE(
                         JSONB_AGG(
                           JSONB_BUILD_OBJECT(
                             'timestamp', ac."TIMESTAMP"
                           , 'comment', ac."COMMENT"
                           , 'commenter', ac."COMMENTER"
                           )
                           ORDER BY ac."TIMESTAMP"
                                  , ac."ID"
                         )
                       , '[]'
                       )
                  FROM "ANALYSISCOMMENT" AS ac
                 WHERE ac."ANALYSIS_ID" = a."ID"
               ) AS "COMMENTS"
          FROM "ANALYSIS" AS a
         WHERE a."COMPONENT_ID" = :componentId
           AND a."VULNERABILITY_ID" = :vulnDbId
        """)
    @Nullable
    AnalysisTrail getTrail(@Bind long componentId, @Bind long vulnDbId);

    @SqlQuery("""
        SELECT "ID"
             , "COMPONENT_ID"
             , "VULNERABILITY_ID"
             , "VULNERABILITY_POLICY_ID"
             , "STATE"
             , "JUSTIFICATION"
             , "RESPONSE"
             , "DETAILS"
             , "SUPPRESSED"
             , "SEVERITY"
             , "CVSSV2VECTOR"
             , "CVSSV2SCORE"
             , "CVSSV3VECTOR"
             , "CVSSV3SCORE"
             , "CVSSV4VECTOR"
             , "CVSSV4SCORE"
             , "OWASPVECTOR"
             , "OWASPSCORE"
          FROM "ANALYSIS"
         WHERE "PROJECT_ID" = :projectId
           AND ("COMPONENT_ID", "VULNERABILITY_ID")
            IN (SELECT * FROM UNNEST(:componentIds, :vulnDbIds))
        """)
    List<Analysis> getAnalyses(@Bind long projectId, @Bind List<Long> componentIds, @Bind List<Long> vulnDbIds);

    default Map<FindingKey, Analysis> getAnalyses(long projectId, Collection<FindingKey> findingKeys) {
        if (findingKeys.isEmpty()) {
            return Map.of();
        }

        final List<FindingKey> keys = List.copyOf(findingKeys);
        return byFindingKey(getAnalyses(
                projectId, columnValues(keys, FindingKey::componentId), columnValues(keys, FindingKey::vulnDbId)));
    }

    @SqlQuery("""
        SELECT "ID"
             , "COMPONENT_ID"
             , "VULNERABILITY_ID"
             , "VULNERABILITY_POLICY_ID"
             , "STATE"
             , "JUSTIFICATION"
             , "RESPONSE"
             , "DETAILS"
             , "SUPPRESSED"
             , "SEVERITY"
             , "CVSSV2VECTOR"
             , "CVSSV2SCORE"
             , "CVSSV3VECTOR"
             , "CVSSV3SCORE"
             , "CVSSV4VECTOR"
             , "CVSSV4SCORE"
             , "OWASPVECTOR"
             , "OWASPSCORE"
          FROM "ANALYSIS"
         WHERE "PROJECT_ID" = :projectId
           AND "VULNERABILITY_POLICY_ID" IS NOT NULL
           AND ("COMPONENT_ID", "VULNERABILITY_ID")
               NOT IN (SELECT * FROM UNNEST(:excludeComponentIds, :excludeVulnDbIds))
        """)
    List<Analysis> getForProjectWithPolicyApplied(
            @Bind long projectId, @Bind List<Long> excludeComponentIds, @Bind List<Long> excludeVulnDbIds);

    default Map<FindingKey, Analysis> getForProjectWithPolicyApplied(
            long projectId, Collection<FindingKey> excludeFindingKeys) {
        final List<FindingKey> keys = List.copyOf(excludeFindingKeys);
        return byFindingKey(getForProjectWithPolicyApplied(
                projectId, columnValues(keys, FindingKey::componentId), columnValues(keys, FindingKey::vulnDbId)));
    }

    private static Map<FindingKey, Analysis> byFindingKey(List<Analysis> analyses) {
        return analyses.stream()
                .collect(Collectors.toMap(
                        analysis -> new FindingKey(analysis.componentId(), analysis.vulnDbId()), Function.identity()));
    }
}
