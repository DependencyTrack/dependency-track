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

import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.persistence.QueryManager;

import java.util.Objects;

public final class AnalysisCommentUtil {

    private AnalysisCommentUtil() { }

    public static boolean makeStateComment(final QueryManager qm, final Analysis analysis, final AnalysisState analysisState, final String commenter) {
        return makeCommentIfChanged("Analysis", qm, analysis, Objects.requireNonNullElse(analysis.getAnalysisState(), AnalysisState.NOT_SET), analysisState, commenter);
    }

    public static void makeJustificationComment(final QueryManager qm, final Analysis analysis, final AnalysisJustification analysisJustification, final String commenter) {
        makeCommentIfChanged("Justification", qm, analysis, Objects.requireNonNullElse(analysis.getAnalysisJustification(), AnalysisJustification.NOT_SET), analysisJustification, commenter);
    }

    public static void makeAnalysisResponseComment(final QueryManager qm, final Analysis analysis, final AnalysisResponse analysisResponse, final String commenter) {
        makeCommentIfChanged("Vendor Response", qm, analysis, Objects.requireNonNullElse(analysis.getAnalysisResponse(), AnalysisResponse.NOT_SET), analysisResponse, commenter);
    }

    public static void makeAnalysisDetailsComment(final QueryManager qm, final Analysis analysis, final String analysisDetails, final String commenter) {
        makeDetailsCommentIfChanged(qm, analysis, Objects.requireNonNullElse(analysis.getAnalysisDetails(), ""), analysisDetails, commenter);
    }

    public static boolean makeAnalysisSuppressionComment(final QueryManager qm, final Analysis analysis, final Boolean suppressed, final String commenter) {
        if (suppressed != null && analysis.isSuppressed() != suppressed) {
            final String message = (suppressed) ? "Suppressed" : "Unsuppressed";
            qm.makeAnalysisComment(analysis, message, commenter);
            return true;
        }
        return false;
    }

    static <T> boolean makeCommentIfChanged(final String prefix, final QueryManager qm, final Analysis analysis, final T currentValue, final T newValue, final String commenter) {
        if (newValue == null || Objects.equals(newValue, currentValue)) {
            return false;
        }

        qm.makeAnalysisComment(analysis, "%s: %s → %s".formatted(prefix, currentValue, newValue), commenter);
        return true;
    }

    static void makeDetailsCommentIfChanged(final QueryManager qm, final Analysis analysis, final String currentValue, final String newValue, final String commenter) {
        if (newValue == null || Objects.equals(newValue, currentValue)) {
            return;
        }

        qm.makeAnalysisComment(analysis, "Details: %s".formatted(newValue), commenter);
    }
}
