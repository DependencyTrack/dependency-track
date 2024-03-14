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

public final class AnalysisCommentUtil {

    private AnalysisCommentUtil() { }


    public static void makeFirstStateComment(final QueryManager qm, final Analysis analysis, final String commenter) {
        if (analysis.getAnalysisState() != null) {
            addAnalysisStateComment(qm, analysis, null, analysis.getAnalysisState(), commenter);
        }
    }

    public static boolean makeStateComment(final QueryManager qm, final Analysis analysis, final AnalysisState analysisState, final String commenter) {
        boolean analysisStateChange = false;
        if (analysisState != null && analysisState != analysis.getAnalysisState()) {
            analysisStateChange = true;
            addAnalysisStateComment(qm, analysis, analysis.getAnalysisState(), analysisState, commenter);
        }
        return analysisStateChange;
    }

    private static void addAnalysisStateComment(QueryManager qm, Analysis analysis, AnalysisState before, AnalysisState after, String commenter) {
        qm.makeAnalysisComment(analysis, String.format("Analysis: %s → %s", before, after), commenter);
    }

    public static void makeFirstJustificationComment(QueryManager qm, Analysis analysis, String commenter) {
        if (analysis.getAnalysisJustification() != null) {
            addAnalysisJustificationComment(qm, analysis, null, analysis.getAnalysisJustification(), commenter);
        }
    }

    public static void makeJustificationComment(final QueryManager qm, final Analysis analysis, final AnalysisJustification analysisJustification, final String commenter) {
        if (analysisJustification != null) {
            if (analysis.getAnalysisJustification() == null && AnalysisJustification.NOT_SET != analysisJustification) {
                addAnalysisJustificationComment(qm, analysis, AnalysisJustification.NOT_SET, analysisJustification, commenter);
            } else if (analysis.getAnalysisJustification() != null && analysisJustification != analysis.getAnalysisJustification()) {
                addAnalysisJustificationComment(qm, analysis, analysis.getAnalysisJustification(), analysisJustification, commenter);
            }
        }
    }

    private static void addAnalysisJustificationComment(QueryManager qm, Analysis analysis, AnalysisJustification before, AnalysisJustification after, String commenter) {
        qm.makeAnalysisComment(analysis, String.format("Justification: %s → %s", before, after), commenter);
    }


    public static void makeFirstAnalysisResponseComment(QueryManager qm, Analysis analysis, String commenter) {
        if (analysis.getAnalysisResponse() != null) {
            addAnalysisResponseComment(qm, analysis, null, analysis.getAnalysisResponse(), commenter);
        }
    }

    public static void makeAnalysisResponseComment(final QueryManager qm, final Analysis analysis, final AnalysisResponse analysisResponse, final String commenter) {
        if (analysisResponse != null) {
            if (analysis.getAnalysisResponse() == null && analysis.getAnalysisResponse() != analysisResponse) {
                addAnalysisResponseComment(qm, analysis, AnalysisResponse.NOT_SET, analysisResponse, commenter);
            } else if (analysis.getAnalysisResponse() != null && analysis.getAnalysisResponse() != analysisResponse) {
                addAnalysisResponseComment(qm, analysis, analysis.getAnalysisResponse(), analysisResponse, commenter);
            }
        }
    }

    private static void addAnalysisResponseComment(QueryManager qm, Analysis analysis, AnalysisResponse before, AnalysisResponse after, String commenter) {
        qm.makeAnalysisComment(analysis, String.format("Vendor Response: %s → %s", before, after), commenter);
    }

    public static void makeFirstDetailsComment(QueryManager qm, Analysis analysis, String commenter) {
        if (analysis.getAnalysisDetails() != null && !analysis.getAnalysisDetails().isEmpty()) {
            addAnalysisDetailsComment(qm, analysis, commenter);
        }
    }

    public static void makeAnalysisDetailsComment(final QueryManager qm, final Analysis analysis, final String analysisDetails, final String commenter) {
        if (analysisDetails != null && !analysisDetails.equals(analysis.getAnalysisDetails())) {
            final String message = "Details: " + analysisDetails.trim();
            qm.makeAnalysisComment(analysis, message, commenter);
        }
    }

    private static void addAnalysisDetailsComment(QueryManager qm, Analysis analysis, String commenter) {
        final String message = "Details: " + analysis.getAnalysisDetails().trim();
        qm.makeAnalysisComment(analysis, message, commenter);
    }

    public static boolean makeAnalysisSuppressionComment(final QueryManager qm, final Analysis analysis, final Boolean suppressed, final String commenter) {
        boolean suppressionChange = false;
        if (suppressed != null && analysis.isSuppressed() != suppressed) {
            suppressionChange = true;
            final String message = (suppressed) ? "Suppressed" : "Unsuppressed";
            qm.makeAnalysisComment(analysis, message, commenter);
        }
        return suppressionChange;
    }


}
