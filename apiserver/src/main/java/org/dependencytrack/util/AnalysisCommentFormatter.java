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
package org.dependencytrack.util;

import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;

import java.util.Optional;

public final class AnalysisCommentFormatter {

    public enum AnalysisCommentField {

        STATE("Analysis", AnalysisState.NOT_SET.name()),
        JUSTIFICATION("Justification", AnalysisJustification.NOT_SET.name()),
        RESPONSE("Vendor Response", AnalysisResponse.NOT_SET.name()),
        DETAILS("Details", "(None)"),
        SUPPRESSED(null, null),
        SEVERITY("Severity", Severity.UNASSIGNED.name()),
        CVSSV2_VECTOR("CVSSv2 Vector", "(None)"),
        CVSSV2_SCORE("CVSSv2 Score", "(None)"),
        CVSSV3_VECTOR("CVSSv3 Vector", "(None)"),
        CVSSV3_SCORE("CVSSv3 Score", "(None)"),
        CVSSV4_VECTOR("CVSSv4 Vector", "(None)"),
        CVSSV4_SCORE("CVSSv4 Score", "(None)"),
        OWASP_VECTOR("OWASP Vector", "(None)"),
        OWASP_SCORE("OWASP Score", "(None)");

        private final String displayName;
        private final String nullValue;

        AnalysisCommentField(final String displayName, final String nullValue) {
            this.displayName = displayName;
            this.nullValue = nullValue;
        }

    }

    private AnalysisCommentFormatter() {
    }

    public static String formatComment(final AnalysisCommentField field, final Object oldValue, final Object newValue) {
        if (field == AnalysisCommentField.SUPPRESSED) {
            return (newValue instanceof final Boolean newValueBoolean && newValueBoolean) ? "Suppressed" : "Unsuppressed";
        }

        final String oldValueString = Optional.ofNullable(oldValue).map(Object::toString).orElse(field.nullValue);
        final String newValueString = Optional.ofNullable(newValue).map(Object::toString).orElse(field.nullValue);
        if (field == AnalysisCommentField.DETAILS) {
            // Details can be fairly long, so we're just recording the new value,
            // without repeating the previous value.
            return "%s: %s".formatted(field.displayName, newValueString);
        }

        return "%s: %s → %s".formatted(field.displayName, oldValueString, newValueString);
    }

}
