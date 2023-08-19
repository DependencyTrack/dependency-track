package org.dependencytrack.parser.spdx.expression;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import java.io.IOException;

import org.dependencytrack.parser.spdx.expression.model.SpdxExpression;
import org.dependencytrack.persistence.QueryManager;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class SpdxExpressionParserTest {
    
    private SpdxExpressionParser parser;

    @Before
    public void setUp() throws Exception {
        parser = new SpdxExpressionParser();
    }

    @Test
    public void testParsingOfSuperfluousParentheses() throws IOException {
        var exp = parser.parse("(Apache OR MIT WITH (CPE) AND GPL WITH ((CC0 OR GPL-2)))");
        assertEquals("OR(Apache, AND(WITH(MIT, CPE), WITH(GPL, OR(CC0, GPL-2))))", exp.toString());
    }

    @Test
    public void testThatAndOperatorBindsStrongerThanOrOperator() throws IOException {
        var exp = parser.parse("LGPL-2.1-only OR BSD-3-Clause AND MIT");
        assertEquals("OR(LGPL-2.1-only, AND(BSD-3-Clause, MIT))", exp.toString());
    }

    @Test
    public void testThatWithOperatorBindsStrongerThanAndOperator() throws IOException {
        var exp = parser.parse("LGPL-2.1-only WITH CPE AND MIT OR BSD-3-Clause");
        assertEquals("OR(AND(WITH(LGPL-2.1-only, CPE), MIT), BSD-3-Clause)", exp.toString());
    }

    @Test
    public void testThatParenthesesOverrideOperatorPrecedence() throws IOException {
        var exp = parser.parse("MIT AND (LGPL-2.1-or-later OR BSD-3-Clause)");
        assertEquals("AND(MIT, OR(LGPL-2.1-or-later, BSD-3-Clause))", exp.toString());
    }

    @Test
    public void testParsingWithMissingSpaceAfterParenthesis() throws IOException {
        var exp = parser.parse("(MIT)AND(LGPL-2.1-or-later WITH(CC0 OR GPL-2))");
        assertEquals("AND(MIT, WITH(LGPL-2.1-or-later, OR(CC0, GPL-2)))", exp.toString());
    }

    @Test
    public void testMissingClosingParenthesis() throws IOException {
        var exp = parser.parse("MIT (OR BSD-3-Clause");
        assertEquals(SpdxExpression.INVALID, exp);
    }

    @Test
    public void testMissingOpeningParenthesis() throws IOException {
        var exp = parser.parse("MIT )(OR BSD-3-Clause");
        assertEquals(SpdxExpression.INVALID, exp);
    }

}
