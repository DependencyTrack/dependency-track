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
package org.dependencytrack.parser.cyclonedx.util;

import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ModelConverterTest {

    /**
     * Reference the production constant directly so a future change to the byte used as the
     * group-key separator forces this test to be re-checked rather than silently passing
     * against a stale literal.
     */
    private static final String SEP = String.valueOf(ModelConverter.FIELD_SEPARATOR);

    @Test
    void analysisFingerprintReturnsEmptyForNullAnalysis() {
        assertThat(ModelConverter.analysisFingerprint(null)).isEmpty();
    }

    @Test
    void analysisFingerprintEmitsEnumNameNotToString() {
        final Analysis analysis = new Analysis();
        analysis.setAnalysisState(AnalysisState.EXPLOITABLE);
        analysis.setAnalysisJustification(AnalysisJustification.CODE_NOT_REACHABLE);
        analysis.setAnalysisResponse(AnalysisResponse.UPDATE);
        analysis.setAnalysisDetails("hand-triaged");

        assertThat(ModelConverter.analysisFingerprint(analysis))
                .isEqualTo("EXPLOITABLE" + SEP + "CODE_NOT_REACHABLE" + SEP + "UPDATE" + SEP + "hand-triaged");
    }

    @Test
    void analysisFingerprintFormatIsStableAcrossNullFields() {
        final Analysis stateOnly = new Analysis();
        stateOnly.setAnalysisState(AnalysisState.EXPLOITABLE);

        // The fingerprint contract is positional — null fields collapse to the empty string so a
        // future "EXPLOITABLE/null/null/null" analysis cannot collide with an analysis whose state
        // happens to render as "EXPLOITABLEnull" via String.valueOf(Object).
        assertThat(ModelConverter.analysisFingerprint(stateOnly))
                .isEqualTo("EXPLOITABLE" + SEP + "" + SEP + "" + SEP + "");
    }

    @Test
    void analysisFingerprintTrimsBlankDetailsToEmpty() {
        final Analysis blankDetails = new Analysis();
        blankDetails.setAnalysisState(AnalysisState.RESOLVED);
        blankDetails.setAnalysisDetails("   ");

        assertThat(ModelConverter.analysisFingerprint(blankDetails))
                .isEqualTo("RESOLVED" + SEP + "" + SEP + "" + SEP + "");
    }

    @Test
    void analysisFingerprintDistinguishesByEachField() {
        final Analysis a = new Analysis();
        a.setAnalysisState(AnalysisState.EXPLOITABLE);
        a.setAnalysisResponse(AnalysisResponse.UPDATE);

        final Analysis b = new Analysis();
        b.setAnalysisState(AnalysisState.EXPLOITABLE);
        b.setAnalysisResponse(AnalysisResponse.WORKAROUND_AVAILABLE);

        assertThat(ModelConverter.analysisFingerprint(a))
                .isNotEqualTo(ModelConverter.analysisFingerprint(b));
    }
}
