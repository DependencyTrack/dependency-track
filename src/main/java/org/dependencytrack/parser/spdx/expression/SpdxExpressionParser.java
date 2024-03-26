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

import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.List;

import org.dependencytrack.parser.spdx.expression.model.SpdxOperator;
import org.dependencytrack.parser.spdx.expression.model.SpdxExpression;

/**
 * This class parses SPDX expressions according to
 * https://spdx.github.io/spdx-spec/v2-draft/SPDX-license-expressions/ into a tree of
 * SpdxExpressions and SpdxExpressionOperations
 * 
 * @author hborchardt
 * @since 4.9.0
 */
public class SpdxExpressionParser {

    /**
     * Reads in a SPDX expression and returns a parsed tree of SpdxExpressionOperators and license
     * ids.
     * 
     * @param spdxExpression
     *            spdx expression string
     * @return parsed SpdxExpression tree, or SpdxExpression.INVALID if an error has occurred during
     *         parsing
     */
    public SpdxExpression parse(final String spdxExpression) {
        // operators are surrounded by spaces or brackets. Let's make our life easier and surround brackets by spaces.
        var _spdxExpression = spdxExpression.replace("(", " ( ").replace(")", " ) ").split(" ");
        if (_spdxExpression.length == 1) {
            return new SpdxExpression(spdxExpression);
        }

        // Shunting yard algorithm to convert SPDX expression to reverse polish notation
        // specify list of infix operators
        List<String> infixOperators = List.of(SpdxOperator.OR.getToken(), SpdxOperator.AND.getToken(),
                SpdxOperator.WITH.getToken());

        ArrayDeque<String> operatorStack = new ArrayDeque<>();
        ArrayDeque<String> outputQueue = new ArrayDeque<>();
        Iterator<String> it = List.of(_spdxExpression).iterator();
        while(it.hasNext()) {
            var token = it.next();
            if (token.length() == 0) {
                continue;
            }
            if (infixOperators.contains(token)) {
                int opPrecedence = SpdxOperator.valueOf(token).getPrecedence();
                for (String o2; (o2 = operatorStack.peek()) != null && !o2.equals("(")
                        && SpdxOperator.valueOf(o2).getPrecedence() > opPrecedence;) {
                    outputQueue.push(operatorStack.pop());
                }
                ;
                operatorStack.push(token);
            } else if (token.equals("(")) {
                operatorStack.push(token);
            } else if (token.equals(")")) {
                for (String o2; (o2 = operatorStack.peek()) == null || !o2.equals("(");) {
                    if (o2 == null) {
                        // Mismatched parentheses
                        return SpdxExpression.INVALID;
                    }
                    outputQueue.push(operatorStack.pop());
                }
                ;
                String leftParens = operatorStack.pop();

                if (!"(".equals(leftParens)) {
                    // Mismatched parentheses
                    return SpdxExpression.INVALID;
                }
                // no function tokens implemented
            } else {
                outputQueue.push(token);
            }
        }
        for (String o2; (o2 = operatorStack.peek()) != null;) {
            if ("(".equals(o2)) {
                // Mismatched parentheses
                return SpdxExpression.INVALID;
            }
            outputQueue.push(operatorStack.pop());
        }

        // convert RPN stack into tree
        // this is easy because all infix operators have two arguments
        ArrayDeque<SpdxExpression> expressions = new ArrayDeque<>();
        SpdxExpression expr = null;
        while (!outputQueue.isEmpty()) {
            var token = outputQueue.pollLast();
            if (infixOperators.contains(token)) {
                var rhs = expressions.pop();
                var lhs = expressions.pop();
                expr = new SpdxExpression(SpdxOperator.valueOf(token), List.of(lhs, rhs));
            } else {
                if (token.endsWith("+")) {
                    // trailing `+` is not a whitespace-delimited operator - process it separately 
                    expr = new SpdxExpression(SpdxOperator.PLUS,
                            List.of(new SpdxExpression(token.substring(0, token.length() - 1))));
                } else {
                    expr = new SpdxExpression(token);
                }
            }
            expressions.push(expr);
        }
        return expr;
    }
}
