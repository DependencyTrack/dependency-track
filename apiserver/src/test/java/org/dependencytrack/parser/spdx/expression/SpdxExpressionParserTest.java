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
package org.dependencytrack.parser.spdx.expression;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class SpdxExpressionParserTest {

    @Test
    void shouldParseSuperfluousParentheses() {
        var exp = SpdxExpressionParser.getInstance().parse("(Apache OR MIT WITH (CPE) AND GPL WITH ((CC0 OR GPL-2)))");
        assertThat(exp).hasToString("OR(AND(WITH(GPL, OR(CC0, GPL-2)), WITH(MIT, CPE)), Apache)");
    }

    @Test
    void shouldBindAndStrongerThanOr() {
        var exp = SpdxExpressionParser.getInstance().parse("LGPL-2.1-only OR BSD-3-Clause AND MIT");
        assertThat(exp).hasToString("OR(AND(BSD-3-Clause, MIT), LGPL-2.1-only)");
    }

    @Test
    void shouldBindWithStrongerThanAnd() {
        var exp = SpdxExpressionParser.getInstance().parse("LGPL-2.1-only WITH CPE AND MIT OR BSD-3-Clause");
        assertThat(exp).hasToString("OR(AND(MIT, WITH(LGPL-2.1-only, CPE)), BSD-3-Clause)");
    }

    @Test
    void shouldOverridePrecedenceWithParentheses() {
        var exp = SpdxExpressionParser.getInstance().parse("MIT AND (LGPL-2.1-or-later OR BSD-3-Clause)");
        assertThat(exp).hasToString("AND(MIT, OR(BSD-3-Clause, LGPL-2.1-or-later))");
    }

    @Test
    void shouldParseWithMissingSpaceAfterParenthesis() {
        var exp = SpdxExpressionParser.getInstance().parse("(MIT)AND(LGPL-2.1-or-later WITH(CC0 OR GPL-2))");
        assertThat(exp).hasToString("AND(MIT, WITH(LGPL-2.1-or-later, OR(CC0, GPL-2)))");
    }

    @Test
    void shouldRejectMissingClosingParenthesis() {
        assertThatExceptionOfType(SpdxExpressionParseException.class)
                .isThrownBy(() -> SpdxExpressionParser.getInstance().parse("MIT (OR BSD-3-Clause"));
    }

    @Test
    void shouldRejectMissingOpeningParenthesis() {
        assertThatExceptionOfType(SpdxExpressionParseException.class)
                .isThrownBy(() -> SpdxExpressionParser.getInstance().parse("MIT )(OR BSD-3-Clause"));
    }

    @Test
    void shouldRejectDanglingOperator() {
        assertThatExceptionOfType(SpdxExpressionParseException.class)
                .isThrownBy(() -> SpdxExpressionParser.getInstance().parse("GPL-3.0-or-later AND GPL-2.0-or-later AND GPL-2.0-only AND"));
    }

    @Test
    void shouldRejectMissingOperand() {
        assertThatExceptionOfType(SpdxExpressionParseException.class)
                .isThrownBy(() -> SpdxExpressionParser.getInstance().parse("MIT OR"));
        assertThatExceptionOfType(SpdxExpressionParseException.class)
                .isThrownBy(() -> SpdxExpressionParser.getInstance().parse("OR MIT"));
        assertThatExceptionOfType(SpdxExpressionParseException.class)
                .isThrownBy(() -> SpdxExpressionParser.getInstance().parse("MIT AND OR Apache-2.0"));
    }

    @Test
    void shouldRejectDanglingOperands() {
        assertThatExceptionOfType(SpdxExpressionParseException.class)
                .isThrownBy(() -> SpdxExpressionParser.getInstance().parse("MIT Apache-2.0"));
    }

    @Test
    void shouldRejectStandalonePlus() {
        assertThatExceptionOfType(SpdxExpressionParseException.class)
                .isThrownBy(() -> SpdxExpressionParser.getInstance().parse("+"));
        assertThatExceptionOfType(SpdxExpressionParseException.class)
                .isThrownBy(() -> SpdxExpressionParser.getInstance().parse("MIT +"));
    }

    @Test
    void shouldRejectCompoundExpressionAsWithLhs() {
        assertThatExceptionOfType(SpdxExpressionParseException.class)
                .isThrownBy(() -> SpdxExpressionParser.getInstance().parse(
                        "(MIT OR BSD-3-Clause) WITH Classpath-exception-2.0"));
    }

    @Test
    void shouldAcceptOrLaterAsWithLhs() {
        var exp = SpdxExpressionParser.getInstance().parse("GPL-2.0+ WITH Classpath-exception-2.0");
        assertThat(exp).hasToString("WITH(+(GPL-2.0), Classpath-exception-2.0)");
    }

    @Test
    void shouldReturnNullFromTryParseOnInvalidInput() {
        assertThat(SpdxExpressionParser.getInstance().tryParse("MIT OR")).isNull();
        assertThat(SpdxExpressionParser.getInstance().tryParse(null)).isNull();
        assertThat(SpdxExpressionParser.getInstance().tryParse("")).isNull();
    }

}
