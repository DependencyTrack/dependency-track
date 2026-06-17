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
package org.dependencytrack.persistence;

import alpine.model.ApiKey;
import alpine.model.User;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.JdoNotificationEmitter;
import org.dependencytrack.notification.NotificationModelConverter;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.dependencytrack.notification.api.NotificationFactory.createVulnerabilityAnalysisDecisionChangeNotification;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

public class AnalysisQueryManager extends QueryManager {


    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    AnalysisQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    AnalysisQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a Analysis for the specified Project, Component, and Vulnerability.
     *
     * @param component     the Component
     * @param vulnerability the Vulnerability
     * @return a Analysis object, or null if not found
     */
    public Analysis getAnalysis(Component component, Vulnerability vulnerability) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "component == :component && vulnerability == :vulnerability");
        query.setRange(0, 1);
        return singleResult(query.execute(component, vulnerability));
    }

    /**
     * @since 5.0.0
     */
    @Override
    public long makeAnalysis(final MakeAnalysisCommand command) {
        assertPersistent(command.component(), "component must be persistent");
        assertPersistent(command.vulnerability(), "vulnerability must be persistent");

        return callInTransaction(() -> {
            final var auditTrailComments = new ArrayList<String>();

            Analysis analysis = getAnalysis(command.component(), command.vulnerability());
            if (analysis == null) {
                analysis = new Analysis();
                analysis.setComponent(command.component());
                analysis.setVulnerability(command.vulnerability());
                analysis.setAnalysisState(AnalysisState.NOT_SET);
                analysis.setAnalysisJustification(AnalysisJustification.NOT_SET);
                analysis.setAnalysisResponse(AnalysisResponse.NOT_SET);
                analysis.setSuppressed(false);
                persist(analysis);
            }

            boolean stateChanged = false;
            boolean suppressionChanged = false;

            if (command.state() != null && command.state() != analysis.getAnalysisState()) {
                auditTrailComments.add("Analysis: %s → %s".formatted(analysis.getAnalysisState(), command.state()));
                analysis.setAnalysisState(command.state());
                stateChanged = true;
            }
            if (command.justification() != null && command.justification() != analysis.getAnalysisJustification()) {
                auditTrailComments.add("Justification: %s → %s".formatted(analysis.getAnalysisJustification(), command.justification()));
                analysis.setAnalysisJustification(command.justification());
            }
            if (command.response() != null && command.response() != analysis.getAnalysisResponse()) {
                auditTrailComments.add("Vendor Response: %s → %s".formatted(analysis.getAnalysisResponse(), command.response()));
                analysis.setAnalysisResponse(command.response());
            }
            if (command.details() != null && !command.details().equals(analysis.getAnalysisDetails())) {
                auditTrailComments.add("Details: %s".formatted(command.details()));
                analysis.setAnalysisDetails(command.details());
            }
            if (command.suppress() != null && command.suppress() != analysis.isSuppressed()) {
                auditTrailComments.add(command.suppress() ? "Suppressed" : "Unsuppressed");
                analysis.setSuppressed(command.suppress());
                suppressionChanged = true;
            }

            final List<String> comments =
                    !command.options().contains(MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL)
                            ? auditTrailComments
                            : new ArrayList<>();
            if (command.comment() != null) {
                comments.add(command.comment());
            }

            createAnalysisComments(analysis, command.commenter(), comments);

            if (!command.options().contains(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)
                    && (stateChanged || suppressionChanged)) {
                new JdoNotificationEmitter(this).emit(
                        createVulnerabilityAnalysisDecisionChangeNotification(
                                NotificationModelConverter.convert(analysis.getProject()),
                                NotificationModelConverter.convert(analysis.getComponent()),
                                NotificationModelConverter.convert(analysis.getVulnerability()),
                                NotificationModelConverter.convert(analysis),
                                stateChanged,
                                suppressionChanged));
            }

            return analysis.getId();
        });
    }

    private void createAnalysisComments(
            final Analysis analysis,
            final String commenter,
            final List<String> comments) {
        assertPersistent(analysis, "analysis must be persistent");

        if (comments == null || comments.isEmpty()) {
            return;
        }

        final var now = new Date();

        final String commenterToUse;
        if (commenter == null) {
            commenterToUse = switch (principal) {
                case User user -> user.getUsername();
                case ApiKey apiKey -> apiKey.getTeams().get(0).getName();
                case null -> null;
                default -> throw new IllegalStateException(
                        "Unexpected principal type: " + principal.getClass().getName());
            };
        } else {
            commenterToUse = commenter;
        }

        runInTransaction(() -> {
            final var analysisComments = new ArrayList<AnalysisComment>(comments.size());

            for (final String comment : comments) {
                final var analysisComment = new AnalysisComment();
                analysisComment.setAnalysis(analysis);
                analysisComment.setCommenter(commenterToUse);
                analysisComment.setComment(comment);
                analysisComment.setTimestamp(now);
                analysisComments.add(analysisComment);
            }

            persist(analysisComments);

            if (analysis.getAnalysisComments() != null) {
                analysis.getAnalysisComments().addAll(analysisComments);
            } else {
                analysis.setAnalysisComments(analysisComments);
            }
        });
    }

}
