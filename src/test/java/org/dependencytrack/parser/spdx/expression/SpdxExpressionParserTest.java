package org.dependencytrack.parser.spdx.expression;

import org.dependencytrack.parser.spdx.expression.model.SpdxExpression;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SpdxExpressionParserTest {

    @Test
    void testParsingOfSuperfluousParentheses() {
        var exp = SpdxExpressionParser.getInstance().parse("(Apache OR MIT WITH (CPE) AND GPL WITH ((CC0 OR GPL-2)))");
        Assertions.assertEquals("OR(Apache, AND(WITH(MIT, CPE), WITH(GPL, OR(CC0, GPL-2))))", exp.toString());
    }

    @Test
    void testThatAndOperatorBindsStrongerThanOrOperator() {
        var exp = SpdxExpressionParser.getInstance().parse("LGPL-2.1-only OR BSD-3-Clause AND MIT");
        Assertions.assertEquals("OR(LGPL-2.1-only, AND(BSD-3-Clause, MIT))", exp.toString());
    }

    @Test
    void testThatWithOperatorBindsStrongerThanAndOperator() {
        var exp = SpdxExpressionParser.getInstance().parse("LGPL-2.1-only WITH CPE AND MIT OR BSD-3-Clause");
        Assertions.assertEquals("OR(AND(WITH(LGPL-2.1-only, CPE), MIT), BSD-3-Clause)", exp.toString());
    }

    @Test
    void testThatParenthesesOverrideOperatorPrecedence() {
        var exp = SpdxExpressionParser.getInstance().parse("MIT AND (LGPL-2.1-or-later OR BSD-3-Clause)");
        Assertions.assertEquals("AND(MIT, OR(LGPL-2.1-or-later, BSD-3-Clause))", exp.toString());
    }

    @Test
    void testParsingWithMissingSpaceAfterParenthesis() {
        var exp = SpdxExpressionParser.getInstance().parse("(MIT)AND(LGPL-2.1-or-later WITH(CC0 OR GPL-2))");
        Assertions.assertEquals("AND(MIT, WITH(LGPL-2.1-or-later, OR(CC0, GPL-2)))", exp.toString());
    }

    @Test
    void testMissingClosingParenthesis() {
        var exp = SpdxExpressionParser.getInstance().parse("MIT (OR BSD-3-Clause");
        Assertions.assertEquals(SpdxExpression.INVALID, exp);
    }

    @Test
    void testMissingOpeningParenthesis() {
        var exp = SpdxExpressionParser.getInstance().parse("MIT )(OR BSD-3-Clause");
        Assertions.assertEquals(SpdxExpression.INVALID, exp);
    }

    @Test
    void testDanglingOperator() {
        var exp = SpdxExpressionParser.getInstance().parse("GPL-3.0-or-later AND GPL-2.0-or-later AND GPL-2.0-only AND");
        Assertions.assertEquals(SpdxExpression.INVALID, exp);
    }

}
