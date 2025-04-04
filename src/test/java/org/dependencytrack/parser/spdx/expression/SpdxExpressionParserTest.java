package org.dependencytrack.parser.spdx.expression;

import static org.mockito.Mockito.mock;

import java.io.IOException;

import org.dependencytrack.parser.spdx.expression.model.SpdxExpression;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SpdxExpressionParserTest {
    
    private SpdxExpressionParser parser;

    @BeforeEach
    public void setUp() throws Exception {
        parser = new SpdxExpressionParser();
    }

    @Test
    void testParsingOfSuperfluousParentheses() throws IOException {
        var exp = parser.parse("(Apache OR MIT WITH (CPE) AND GPL WITH ((CC0 OR GPL-2)))");
        Assertions.assertEquals("OR(Apache, AND(WITH(MIT, CPE), WITH(GPL, OR(CC0, GPL-2))))", exp.toString());
    }

    @Test
    void testThatAndOperatorBindsStrongerThanOrOperator() throws IOException {
        var exp = parser.parse("LGPL-2.1-only OR BSD-3-Clause AND MIT");
        Assertions.assertEquals("OR(LGPL-2.1-only, AND(BSD-3-Clause, MIT))", exp.toString());
    }

    @Test
    void testThatWithOperatorBindsStrongerThanAndOperator() throws IOException {
        var exp = parser.parse("LGPL-2.1-only WITH CPE AND MIT OR BSD-3-Clause");
        Assertions.assertEquals("OR(AND(WITH(LGPL-2.1-only, CPE), MIT), BSD-3-Clause)", exp.toString());
    }

    @Test
    void testThatParenthesesOverrideOperatorPrecedence() throws IOException {
        var exp = parser.parse("MIT AND (LGPL-2.1-or-later OR BSD-3-Clause)");
        Assertions.assertEquals("AND(MIT, OR(LGPL-2.1-or-later, BSD-3-Clause))", exp.toString());
    }

    @Test
    void testParsingWithMissingSpaceAfterParenthesis() throws IOException {
        var exp = parser.parse("(MIT)AND(LGPL-2.1-or-later WITH(CC0 OR GPL-2))");
        Assertions.assertEquals("AND(MIT, WITH(LGPL-2.1-or-later, OR(CC0, GPL-2)))", exp.toString());
    }

    @Test
    void testMissingClosingParenthesis() throws IOException {
        var exp = parser.parse("MIT (OR BSD-3-Clause");
        Assertions.assertEquals(SpdxExpression.INVALID, exp);
    }

    @Test
    void testMissingOpeningParenthesis() throws IOException {
        var exp = parser.parse("MIT )(OR BSD-3-Clause");
        Assertions.assertEquals(SpdxExpression.INVALID, exp);
    }

}
