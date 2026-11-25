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
package org.dependencytrack.persistence.command;

import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.notification.proto.v1.Group;

import java.math.BigDecimal;
import java.util.Collections;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * @param componentId   ID of the component to make the analysis for
 * @param vulnDbId      Database ID of the vulnerability to make the analysis for
 * @param state         The analysis state to set
 * @param justification The justification to set
 * @param response      The vendor response to set
 * @param details       The details to set
 * @param suppress      Whether to suppress the finding
 * @param commenter     Name of the principal on which behalf audit trail entries will be created
 * @param comment       The comment to add to the audit trail
 * @param owaspVector   The OWASP Risk Rating vector to set
 * @param owaspScore    The OWASP Risk Rating score to set
 * @param options       Additional options
 * @since 5.0.0
 */
public record MakeAnalysisCommand(
        long componentId,
        long vulnDbId,
        AnalysisState state,
        AnalysisJustification justification,
        AnalysisResponse response,
        String details,
        Boolean suppress,
        String commenter,
        String comment,
        String owaspVector,
        BigDecimal owaspScore,
        Set<Option> options) {

    public enum Option {

        /**
         * Do not generate any audit trail entries.
         * Will still create a comment entry if {@code comment} is provided.
         */
        OMIT_AUDIT_TRAIL,

        /**
         * Do not create a comment entry for {@code comment} if the command did not change the analysis.
         */
        OMIT_COMMENT_IF_UNCHANGED,

        /**
         * Do not emit any {@link Group#GROUP_PROJECT_AUDIT_CHANGE} notifications.
         */
        OMIT_NOTIFICATION
    }

    public MakeAnalysisCommand {
        requireNonNull(options, "options must not be null");
    }

    public MakeAnalysisCommand(final long componentId, final long vulnDbId) {
        this(componentId, vulnDbId, null, null, null, null, null, null, null, null, null, Collections.emptySet());
    }

    public MakeAnalysisCommand withState(final AnalysisState state) {
        return new MakeAnalysisCommand(
                this.componentId,
                this.vulnDbId,
                state,
                this.justification,
                this.response,
                this.details,
                this.suppress,
                this.commenter,
                this.comment,
                this.owaspVector,
                this.owaspScore,
                this.options);
    }

    public MakeAnalysisCommand withJustification(final AnalysisJustification justification) {
        return new MakeAnalysisCommand(
                this.componentId,
                this.vulnDbId,
                this.state,
                justification,
                this.response,
                this.details,
                this.suppress,
                this.commenter,
                this.comment,
                this.owaspVector,
                this.owaspScore,
                this.options);
    }

    public MakeAnalysisCommand withResponse(final AnalysisResponse response) {
        return new MakeAnalysisCommand(
                this.componentId,
                this.vulnDbId,
                this.state,
                this.justification,
                response,
                this.details,
                this.suppress,
                this.commenter,
                this.comment,
                this.owaspVector,
                this.owaspScore,
                this.options);
    }

    public MakeAnalysisCommand withDetails(final String detail) {
        return new MakeAnalysisCommand(
                this.componentId,
                this.vulnDbId,
                this.state,
                this.justification,
                this.response,
                detail,
                this.suppress,
                this.commenter,
                this.comment,
                this.owaspVector,
                this.owaspScore,
                this.options);
    }

    public MakeAnalysisCommand withSuppress(final Boolean suppress) {
        return new MakeAnalysisCommand(
                this.componentId,
                this.vulnDbId,
                this.state,
                this.justification,
                this.response,
                this.details,
                suppress,
                this.commenter,
                this.comment,
                this.owaspVector,
                this.owaspScore,
                this.options);
    }

    public MakeAnalysisCommand withCommenter(final String commenter) {
        return new MakeAnalysisCommand(
                this.componentId,
                this.vulnDbId,
                this.state,
                this.justification,
                this.response,
                this.details,
                this.suppress,
                commenter,
                this.comment,
                this.owaspVector,
                this.owaspScore,
                this.options);
    }

    public MakeAnalysisCommand withComment(final String comment) {
        return new MakeAnalysisCommand(
                this.componentId,
                this.vulnDbId,
                this.state,
                this.justification,
                this.response,
                this.details,
                this.suppress,
                this.commenter,
                comment,
                this.owaspVector,
                this.owaspScore,
                this.options);
    }

    public MakeAnalysisCommand withOwasp(final String owaspVector, final BigDecimal owaspScore) {
        return new MakeAnalysisCommand(
                this.componentId,
                this.vulnDbId,
                this.state,
                this.justification,
                this.response,
                this.details,
                this.suppress,
                this.commenter,
                this.comment,
                owaspVector,
                owaspScore,
                this.options);
    }

    public MakeAnalysisCommand withOptions(final Set<Option> options) {
        return new MakeAnalysisCommand(
                this.componentId,
                this.vulnDbId,
                this.state,
                this.justification,
                this.response,
                this.details,
                this.suppress,
                this.commenter,
                this.comment,
                this.owaspVector,
                this.owaspScore,
                options);
    }
}
