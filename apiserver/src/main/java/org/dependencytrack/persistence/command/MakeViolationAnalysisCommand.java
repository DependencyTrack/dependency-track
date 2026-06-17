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

import org.dependencytrack.model.Component;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.notification.proto.v1.Group;

import java.util.Collections;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * @param component The component to make the analysis for
 * @param violation The policy violation to make the analysis for
 * @param state     The analysis state to set
 * @param suppress  Whether to suppress the violation
 * @param commenter Name of the principal on which behalf audit trail entries will be created
 * @param comment   The comment to add to the audit trail
 * @param options   Additional options
 * @since 5.0.0
 */
public record MakeViolationAnalysisCommand(
        Component component,
        PolicyViolation violation,
        ViolationAnalysisState state,
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

    public MakeViolationAnalysisCommand {
        requireNonNull(component, "component must not be null");
        requireNonNull(violation, "violation must not be null");
        requireNonNull(options, "options must not be null");
    }

    public MakeViolationAnalysisCommand(final Component component, final PolicyViolation violation) {
        this(component, violation, null, null, null, null, Collections.emptySet());
    }

    public MakeViolationAnalysisCommand withState(final ViolationAnalysisState state) {
        return new MakeViolationAnalysisCommand(this.component, this.violation, state, this.suppress, this.commenter, this.comment, this.options);
    }

    public MakeViolationAnalysisCommand withSuppress(final Boolean suppress) {
        return new MakeViolationAnalysisCommand(this.component, this.violation, this.state, suppress, this.commenter, this.comment, this.options);
    }

    public MakeViolationAnalysisCommand withCommenter(final String commenter) {
        return new MakeViolationAnalysisCommand(this.component, this.violation, this.state, this.suppress, commenter, this.comment, this.options);
    }

    public MakeViolationAnalysisCommand withComment(final String comment) {
        return new MakeViolationAnalysisCommand(this.component, this.violation, this.state, this.suppress, this.commenter, comment, this.options);
    }

    public MakeViolationAnalysisCommand withOptions(final Set<Option> options) {
        return new MakeViolationAnalysisCommand(this.component, this.violation, this.state, this.suppress, this.commenter, this.comment, options);
    }

}
