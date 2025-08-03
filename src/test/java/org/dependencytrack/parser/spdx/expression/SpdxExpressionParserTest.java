package org.dependencytrack.parser.spdx.expression;

import org.dependencytrack.parser.spdx.expression.model.SpdxExpression;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class SpdxExpressionParserTest {

    @Test
    public void testParsingOfSuperfluousParentheses() {
        var exp = SpdxExpressionParser.getInstance().parse("(Apache OR MIT WITH (CPE) AND GPL WITH ((CC0 OR GPL-2)))");
        assertEquals("OR(Apache, AND(WITH(MIT, CPE), WITH(GPL, OR(CC0, GPL-2))))", exp.toString());
    }

    @Test
    public void testThatAndOperatorBindsStrongerThanOrOperator() {
        var exp = SpdxExpressionParser.getInstance().parse("LGPL-2.1-only OR BSD-3-Clause AND MIT");
        assertEquals("OR(LGPL-2.1-only, AND(BSD-3-Clause, MIT))", exp.toString());
    }

    @Test
    public void testThatWithOperatorBindsStrongerThanAndOperator() {
        var exp = SpdxExpressionParser.getInstance().parse("LGPL-2.1-only WITH CPE AND MIT OR BSD-3-Clause");
        assertEquals("OR(AND(WITH(LGPL-2.1-only, CPE), MIT), BSD-3-Clause)", exp.toString());
    }

    @Test
    public void testThatParenthesesOverrideOperatorPrecedence() {
        var exp = SpdxExpressionParser.getInstance().parse("MIT AND (LGPL-2.1-or-later OR BSD-3-Clause)");
        assertEquals("AND(MIT, OR(LGPL-2.1-or-later, BSD-3-Clause))", exp.toString());
    }

    @Test
    public void testParsingWithMissingSpaceAfterParenthesis() {
        var exp = SpdxExpressionParser.getInstance().parse("(MIT)AND(LGPL-2.1-or-later WITH(CC0 OR GPL-2))");
        assertEquals("AND(MIT, WITH(LGPL-2.1-or-later, OR(CC0, GPL-2)))", exp.toString());
    }

    @Test
    public void testMissingClosingParenthesis() {
        var exp = SpdxExpressionParser.getInstance().parse("MIT (OR BSD-3-Clause");
        assertEquals(SpdxExpression.INVALID, exp);
    }

    @Test
    public void testMissingOpeningParenthesis() {
        var exp = SpdxExpressionParser.getInstance().parse("MIT )(OR BSD-3-Clause");
        assertEquals(SpdxExpression.INVALID, exp);
    }

    @Test
    public void testDanglingOperator() {
        var exp = SpdxExpressionParser.getInstance().parse("GPL-3.0-or-later AND GPL-2.0-or-later AND GPL-2.0-only AND");
        assertEquals(SpdxExpression.INVALID, exp);
    }

}
