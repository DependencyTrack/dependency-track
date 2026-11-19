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

import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.NotificationSubjectDao;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.PolicyViolationAnalysis;
import org.dependencytrack.persistence.command.MakeViolationAnalysisCommand;
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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

import static org.dependencytrack.notification.api.NotificationFactory.createPolicyViolationAnalysisDecisionChangeNotification;
import static org.dependencytrack.support.jdbi.binding.Bindings.columnValues;

/// @since 5.3.0
@NullMarked
@RegisterConstructorMapper(ViolationAnalysisDao.Analysis.class)
@RegisterConstructorMapper(ViolationAnalysisDao.AnalysisTrail.class)
public interface ViolationAnalysisDao extends SqlObject {

    record Analysis(long id, ViolationAnalysisState state, boolean suppressed) {}

    record CreateCommentCommand(long analysisId, @Nullable String commenter, String comment) {}

    record AnalysisTrail(
            ViolationAnalysisState state,
            boolean suppressed,
            @Json List<Comment> comments) {

        public record Comment(
                Instant timestamp, String comment, @Nullable String commenter) {}
    }

    @SqlUpdate("""
        INSERT INTO "VIOLATIONANALYSIS" (
          "PROJECT_ID"
        , "COMPONENT_ID"
        , "POLICYVIOLATION_ID"
        , "STATE"
        , "SUPPRESSED"
        )
        SELECT "PROJECT_ID"
             , "COMPONENT_ID"
             , "ID"
             , 'NOT_SET'
             , FALSE
          FROM "POLICYVIOLATION"
         WHERE "ID" = :violationId
           AND "COMPONENT_ID" = :componentId
        ON CONFLICT ("PROJECT_ID", "COMPONENT_ID", "POLICYVIOLATION_ID") DO NOTHING
        RETURNING "ID"
                , "STATE"
                , "SUPPRESSED"
        """)
    @GetGeneratedKeys
    @Nullable
    Analysis createAnalysisIfMissing(@Bind long componentId, @Bind long violationId);

    @SqlQuery("""
        SELECT "ID"
             , "STATE"
             , "SUPPRESSED"
          FROM "VIOLATIONANALYSIS"
         WHERE "COMPONENT_ID" = :componentId
           AND "POLICYVIOLATION_ID" = :violationId
           FOR UPDATE
        """)
    @Nullable
    Analysis getAndLockAnalysis(@Bind long componentId, @Bind long violationId);

    @SqlUpdate("""
        UPDATE "VIOLATIONANALYSIS"
           SET "STATE" = :state
             , "SUPPRESSED" = :suppressed
         WHERE "ID" = :id
        """)
    void updateAnalysis(@BindMethods Analysis analysis);

    default int createComments(List<CreateCommentCommand> commands) {
        if (commands.isEmpty()) {
            return 0;
        }

        return getHandle()
                .createUpdate("""
                    INSERT INTO "VIOLATIONANALYSISCOMMENT" ("VIOLATIONANALYSIS_ID", "COMMENTER", "COMMENT", "TIMESTAMP")
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

    default long makeAnalysis(MakeViolationAnalysisCommand command) {
        if (!getHandle().isInTransaction()) {
            throw new IllegalStateException("Must be called within a transaction");
        }

        Analysis current = getAndLockAnalysis(command.componentId(), command.violationId());
        if (current == null) {
            current = createAnalysisIfMissing(command.componentId(), command.violationId());
        }
        if (current == null) {
            // A concurrent transaction created it after the first lookup's snapshot was taken.
            current = getAndLockAnalysis(command.componentId(), command.violationId());
        }
        if (current == null) {
            throw new NoSuchElementException("Policy violation %d of component %d does not exist"
                    .formatted(command.violationId(), command.componentId()));
        }

        final var updated = new Analysis(
                current.id(),
                command.state() != null ? command.state() : current.state(),
                command.suppress() != null ? command.suppress() : current.suppressed());

        final boolean stateChanged = updated.state() != current.state();
        final boolean suppressionChanged = updated.suppressed() != current.suppressed();

        final var comments = new ArrayList<String>();
        if (stateChanged) {
            comments.add("%s → %s".formatted(current.state(), updated.state()));
        }
        if (suppressionChanged) {
            comments.add(updated.suppressed() ? "Suppressed" : "Unsuppressed");
        }

        if (stateChanged || suppressionChanged) {
            updateAnalysis(updated);
        }

        if (command.options().contains(MakeViolationAnalysisCommand.Option.OMIT_AUDIT_TRAIL)) {
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

        if (!command.options().contains(MakeViolationAnalysisCommand.Option.OMIT_NOTIFICATION)
                && (stateChanged || suppressionChanged)) {
            final List<Notification> notifications = getHandle()
                    .attach(NotificationSubjectDao.class)
                    .getForViolationAnalysisDecisionChanges(List.of(command.violationId()))
                    .stream()
                    .map(subject -> createPolicyViolationAnalysisDecisionChangeNotification(
                            subject.getProject(),
                            subject.getComponent(),
                            subject.getPolicyViolation(),
                            PolicyViolationAnalysis.newBuilder()
                                    .setProject(subject.getProject())
                                    .setComponent(subject.getComponent())
                                    .setPolicyViolation(subject.getPolicyViolation())
                                    .setState(updated.state().name())
                                    .setSuppressed(updated.suppressed())
                                    .build(),
                            stateChanged,
                            suppressionChanged))
                    .toList();
            new JdbiNotificationEmitter(getHandle()).emitAll(notifications);
        }

        return current.id();
    }

    @SqlQuery("""
        SELECT va."STATE"
             , va."SUPPRESSED"
             , (SELECT COALESCE(
                         JSONB_AGG(
                           JSONB_BUILD_OBJECT(
                             'timestamp', vac."TIMESTAMP"
                           , 'comment', vac."COMMENT"
                           , 'commenter', vac."COMMENTER"
                           )
                           ORDER BY vac."TIMESTAMP"
                                  , vac."ID"
                         )
                       , '[]'
                       )
                  FROM "VIOLATIONANALYSISCOMMENT" AS vac
                 WHERE vac."VIOLATIONANALYSIS_ID" = va."ID"
               ) AS "COMMENTS"
          FROM "VIOLATIONANALYSIS" AS va
         WHERE va."COMPONENT_ID" = :componentId
           AND va."POLICYVIOLATION_ID" = :violationId
        """)
    @Nullable
    AnalysisTrail getTrail(@Bind long componentId, @Bind long violationId);
}
