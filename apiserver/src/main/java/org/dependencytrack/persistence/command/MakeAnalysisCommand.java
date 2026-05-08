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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.proto.v1.Group;

import java.util.Collections;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * @param component     The component to make the analysis for
 * @param vulnerability The vulnerability to make the analysis for
 * @param state         The analysis state to set
 * @param justification The justification to set
 * @param response      The vendor response to set
 * @param details       The details to set
 * @param suppress      Whether to suppress the finding
 * @param commenter     Name of the principal on which behalf audit trail entries will be created
 * @param comment       The comment to add to the audit trail
 * @param options       Additional options
 * @since 5.0.0
 */
public record MakeAnalysisCommand(
        Component component,
        Vulnerability vulnerability,
        AnalysisState state,
        AnalysisJustification justification,
        AnalysisResponse response,
        String details,
        Boolean suppress,
        String commenter,
        String comment,
        Set<Option> options) {

    public enum Option {

        /**
         * Do not generate any audit trail entries.
         * Will still create a comment entry if {@code comment} is provided.
         */
        OMIT_AUDIT_TRAIL,

        /**
         * Do not emit any {@link Group#GROUP_PROJECT_AUDIT_CHANGE} notifications.
         */
        OMIT_NOTIFICATION

    }

    public MakeAnalysisCommand {
        requireNonNull(component, "component must not be null");
        requireNonNull(vulnerability, "vulnerability must not be null");
        requireNonNull(options, "options must not be null");
    }

    public MakeAnalysisCommand(final Component component, final Vulnerability vulnerability) {
        this(component, vulnerability, null, null, null, null, null, null, null, Collections.emptySet());
    }

    public MakeAnalysisCommand withState(final AnalysisState state) {
        return new MakeAnalysisCommand(this.component, this.vulnerability, state, this.justification, this.response, this.details, this.suppress, this.commenter, this.comment, this.options);
    }

    public MakeAnalysisCommand withJustification(final AnalysisJustification justification) {
        return new MakeAnalysisCommand(this.component, this.vulnerability, this.state, justification, this.response, this.details, this.suppress, this.commenter, this.comment, this.options);
    }

    public MakeAnalysisCommand withResponse(final AnalysisResponse response) {
        return new MakeAnalysisCommand(this.component, this.vulnerability, this.state, this.justification, response, this.details, this.suppress, this.commenter, this.comment, this.options);
    }

    public MakeAnalysisCommand withDetails(final String detail) {
        return new MakeAnalysisCommand(this.component, this.vulnerability, this.state, this.justification, this.response, detail, this.suppress, this.commenter, this.comment, this.options);
    }

    public MakeAnalysisCommand withSuppress(final Boolean suppress) {
        return new MakeAnalysisCommand(this.component, this.vulnerability, this.state, this.justification, this.response, this.details, suppress, this.commenter, this.comment, this.options);
    }

    public MakeAnalysisCommand withCommenter(final String commenter) {
        return new MakeAnalysisCommand(this.component, this.vulnerability, this.state, this.justification, this.response, this.details, this.suppress, commenter, this.comment, this.options);
    }

    public MakeAnalysisCommand withComment(final String comment) {
        return new MakeAnalysisCommand(this.component, this.vulnerability, this.state, this.justification, this.response, this.details, this.suppress, this.commenter, comment, this.options);
    }

    public MakeAnalysisCommand withOptions(final Set<Option> options) {
        return new MakeAnalysisCommand(this.component, this.vulnerability, this.state, this.justification, this.response, this.details, this.suppress, this.commenter, this.comment, options);
    }

}
