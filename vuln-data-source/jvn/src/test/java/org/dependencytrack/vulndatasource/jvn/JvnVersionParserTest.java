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
package org.dependencytrack.vulndatasource.jvn;

import org.dependencytrack.vulndatasource.jvn.JvnVersionParser.ExactVersion;
import org.dependencytrack.vulndatasource.jvn.JvnVersionParser.Result;
import org.dependencytrack.vulndatasource.jvn.JvnVersionParser.Unparseable;
import org.dependencytrack.vulndatasource.jvn.JvnVersionParser.VersionRange;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * Cases are drawn from real JVN {@code VersionNumber} strings observed in the last month of data.
 */
class JvnVersionParserTest {

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            "0.15.0 以上 0.15.2 未満 ; vers:generic/>=0.15.0|<0.15.2",
            "0.2.2 以上 3.19.0 未満   ; vers:generic/>=0.2.2|<3.19.0",
            "0.32.0 未満             ; vers:generic/<0.32.0",
            "1.0 から 3.1.1          ; vers:generic/>=1.0|<=3.1.1",
            "0.9.5 およびそれ以前      ; vers:generic/<=0.9.5",
            "5.0 以前                ; vers:generic/<=5.0",
            "1.2.3 以上              ; vers:generic/>=1.2.3",
    })
    void parsesRanges(final String input, final String expectedVers) {
        final Result result = JvnVersionParser.parse(input, "generic");
        final VersionRange range = assertInstanceOf(VersionRange.class, result);
        assertEquals(expectedVers, range.vers().toString());
    }

    @Test
    void parsesExactVersion() {
        final Result result = JvnVersionParser.parse("25.3.3.1", "generic");
        final ExactVersion exact = assertInstanceOf(ExactVersion.class, result);
        assertEquals("25.3.3.1", exact.version());
    }

    @Test
    void parsesWaveDashRange() {
        final Result result = JvnVersionParser.parse("1.000A〜1.014Q", "generic");
        final VersionRange range = assertInstanceOf(VersionRange.class, result);
        assertEquals("vers:generic/>=1.000A|<=1.014Q", range.vers().toString());
    }

    @Test
    void parsesAllVersionsAsWildcardRange() {
        final Result result = JvnVersionParser.parse("すべてのバージョン", "generic");
        final VersionRange range = assertInstanceOf(VersionRange.class, result);
        assertEquals("vers:generic/*", range.vers().toString());
    }

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            // Platform/edition qualifiers carry no version information; NVD encodes them in
            // separate CPE attributes, so stripping them yields the NVD-equivalent version value.
            "5.0 (client)                        ; 5.0",
            "3 (x86-64)                          ; 3",
            "4.0 (x86-64)                        ; 4.0",
            "Version 1809 for x64-based Systems  ; 1809",
            "Version 22H2 for ARM64-based Systems; 22H2",
            "2019 for 64-bit editions            ; 2019",
            "12.04 LTS                           ; 12.04",
            "11 Express                          ; 11",
            "2013 SP1                            ; 2013",
            "2000 Gold                           ; 2000",
            "R2 for x64-based Systems SP1        ; R2",
            "2016 (32 ビット版)                   ; 2016",
            "2013 SP1 (32-bit editions)          ; 2013",
            "2013 RT SP1                         ; 2013",
            "LTSC 2021 for 32-bit editions       ; 2021",
            "Standard Version 6                  ; 6",
            "- Web Edition Version 4             ; 4",
            "2.5.1 (sparc)                       ; 2.5.1",
    })
    void salvagesQualifiedVersions(final String input, final String expectedVersion) {
        final Result result = JvnVersionParser.parse(input, "generic");
        final ExactVersion exact = assertInstanceOf(ExactVersion.class, result);
        assertEquals(expectedVersion, exact.version());
    }

    @Test
    void salvagesQualifiedRange() {
        final Result result = JvnVersionParser.parse("10.5.x から 10.5.8 まで (32 ビット版)", "generic");
        final VersionRange range = assertInstanceOf(VersionRange.class, result);
        assertEquals("vers:generic/>=10.5.x|<=10.5.8", range.vers().toString());
    }

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            // Cisco-style parenthesized build numbers are exact version values in NVD's CPEs
            // and must be kept verbatim, not stripped down to "11.0".
            "11.0(20.3)   ; 11.0(20.3)",
            "11.1(15)ca   ; 11.1(15)ca",
            "12.0(3.4)T1  ; 12.0(3.4)T1",
    })
    void parsesParenthesizedBuildVersions(final String input, final String expectedVersion) {
        final Result result = JvnVersionParser.parse(input, "generic");
        final ExactVersion exact = assertInstanceOf(ExactVersion.class, result);
        assertEquals(expectedVersion, exact.version());
    }

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            // Qualifier-only texts must not be salvaged into an invented version value.
            "(Server Core installation)",
            "for x64-based Systems",
            "(x64) SP2",
            // Parenthesized content that is neither qualifier vocabulary nor a build number
            // must stay untouched rather than be guessed at.
            "2017 version 15.9 (includes 15.0 - 15.8)",
            "10.01 (SD-UX version B.10.10)",
    })
    void degradesOnQualifierOnlyOrNonQualifierParens(final String input) {
        assertInstanceOf(Unparseable.class, JvnVersionParser.parse(input, "generic"));
    }

    @Test
    void degradesOnNull() {
        assertInstanceOf(Unparseable.class, JvnVersionParser.parse(null, "generic"));
    }
}
