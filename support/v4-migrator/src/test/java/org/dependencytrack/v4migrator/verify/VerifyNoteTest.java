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
package org.dependencytrack.v4migrator.verify;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit coverage for {@link VerifyPhase#note}, the per-table row-count discrepancy classifier.
 */
class VerifyNoteTest {

    private static final Set<String> NO_PROBES = Set.of();

    @Test
    void noReductionYieldsBlankNote() {
        assertThat(VerifyPhase.note("LICENSE", 100L, 100L, 100L, NO_PROBES)).isEmpty();
    }

    @Test
    void increaseYieldsBlankNote() {
        // Fan-out can make v5 exceed source; that is not a reduction.
        assertThat(VerifyPhase.note("TEAMS_PERMISSIONS", 5L, 8L, 8L, NO_PROBES)).isEmpty();
    }

    @Test
    void singlePopulatedStageNeverWarns() {
        // Post-bootstrap shape: only the seeded v5 count is known.
        assertThat(VerifyPhase.note("PERMISSION", null, null, 120L, NO_PROBES)).isEmpty();
    }

    @Test
    void documentedReductionRendersExpected() {
        final String note = VerifyPhase.note("TEAM", 50L, 40L, 40L, NO_PROBES);
        assertThat(note).startsWith("expected: dedup by NAME").endsWith("(-10)");
    }

    @Test
    void documentedReductionTakesPrecedenceOverProbe() {
        // PROJECT is both deduped and probed for invalid UUIDs; the specific note wins.
        final String note = VerifyPhase.note("PROJECT", 30L, 25L, 25L, Set.of("PROJECT"));
        assertThat(note).startsWith("expected: ");
    }

    @Test
    void probedReductionPointsToProbesSection() {
        final String note = VerifyPhase.note("SOMETABLE", 100L, 90L, 90L, Set.of("SOMETABLE"));
        assertThat(note).isEqualTo("see [Probes] (-10)");
    }

    @Test
    void undocumentedReductionShowsNeutralPointer() {
        // Reductions are intentional transforms, not data loss, so the fallback is a neutral
        // pointer rather than an alarm.
        final String note = VerifyPhase.note("SOMETABLE", 100L, 100L, 95L, NO_PROBES);
        assertThat(note).isEqualTo("reduction (-5), see migration guide");
    }

    @Test
    void permissionFanOutTableRendersExpectedOnNetReduction() {
        // When dropped v4-only permissions outnumber the fan-out, the documented note applies.
        final String note = VerifyPhase.note("TEAMS_PERMISSIONS", 20L, 17L, 17L, NO_PROBES);
        assertThat(note).startsWith("expected: ");
    }

    @Test
    void derivedTableReductionComparesStagingToV5() {
        // Derived table: no source. ON CONFLICT can drop rows between staging and v5.
        final String note = VerifyPhase.note("PROJECT_ACCESS_USERS", null, 10L, 8L, NO_PROBES);
        assertThat(note).startsWith("expected: ").endsWith("(-2)");
    }

    @Test
    void outputIsAsciiOnly() {
        final String note = VerifyPhase.note("SOMETABLE", 100L, 100L, 95L, NO_PROBES);
        assertThat(note.chars().allMatch(c -> c < 128)).isTrue();
    }
}
