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

import org.dependencytrack.parser.spdx.expression.SpdxExpressionToken.Grouping;
import org.dependencytrack.parser.spdx.expression.SpdxExpressionToken.Identifier;
import org.dependencytrack.parser.spdx.expression.SpdxExpressionToken.Operator;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Parses SPDX license expressions as defined in
 * <a href="https://spdx.github.io/spdx-spec/v2-draft/SPDX-license-expressions/">the SPDX spec</a>
 * into a tree of {@link SpdxExpression} nodes.
 *
 * @author hborchardt
 * @since 4.9.0
 */
public final class SpdxExpressionParser {

    private static final SpdxExpressionParser INSTANCE = new SpdxExpressionParser();
    private static final Pattern TOKEN_PATTERN = Pattern.compile("[()]|[^\\s()]+");

    private SpdxExpressionParser() {
    }

    public static SpdxExpressionParser getInstance() {
        return INSTANCE;
    }

    /**
     * Parses an SPDX expression.
     *
     * @param expression The expression to parse.
     * @return The parsed {@link SpdxExpression}.
     * @throws SpdxExpressionParseException When parsing failed.
     */
    public SpdxExpression parse(String expression) {
        if (expression == null || expression.isBlank()) {
            throw new SpdxExpressionParseException("Expression must not be null or blank");
        }

        final var cursor = new TokenCursor(tokenize(expression));

        final SpdxExpression result = parseOrExpression(cursor);
        if (cursor.hasNext()) {
            throw new SpdxExpressionParseException(
                    "Unexpected token after expression: " + cursor.next());
        }

        return result;
    }

    /**
     * Parses an SPDX expression, returning {@code null} on failure.
     *
     * @param expression The expression to parse.
     * @return The parsed {@link SpdxExpression}, or {@code null} when parsing failed.
     */
    public @Nullable SpdxExpression tryParse(@Nullable String expression) {
        if (expression == null) {
            return null;
        }

        try {
            return parse(expression);
        } catch (SpdxExpressionParseException e) {
            return null;
        }
    }

    private List<SpdxExpressionToken> tokenize(String expression) {
        final var tokens = new ArrayList<SpdxExpressionToken>();
        final var matcher = TOKEN_PATTERN.matcher(expression);

        while (matcher.find()) {
            final String rawToken = matcher.group();

            if ("(".equals(rawToken)) {
                tokens.add(Grouping.LEFT_PAREN);
            } else if (")".equals(rawToken)) {
                tokens.add(Grouping.RIGHT_PAREN);
            } else if ("+".equals(rawToken)) {
                throw new SpdxExpressionParseException("Standalone '+' operator");
            } else if (rawToken.length() > 1 && rawToken.endsWith("+")) {
                addIdentifierTokens(rawToken.substring(0, rawToken.length() - 1), tokens);
                tokens.add(new Operator(SpdxExpressionOperator.PLUS));
            } else {
                final SpdxExpressionOperator op = SpdxExpressionOperator.ofToken(rawToken);
                if (op != null && op != SpdxExpressionOperator.PLUS) {
                    tokens.add(new Operator(op));
                } else {
                    addIdentifierTokens(rawToken, tokens);
                }
            }
        }

        return tokens;
    }

    private void addIdentifierTokens(String id, List<SpdxExpressionToken> tokens) {
        final String resolved = SpdxLicenseRegistry.resolveWithCompound(id);
        if (resolved != null) {
            tokens.addAll(tokenize(resolved));
        } else {
            tokens.add(new Identifier(id));
        }
    }

    private static SpdxExpression parseOrExpression(TokenCursor cursor) {
        final var operands = new ArrayList<SpdxExpression>();

        do {
            operands.add(parseAndExpression(cursor));
        } while (cursor.matchOperator(SpdxExpressionOperator.OR));

        if (operands.size() == 1) {
            return operands.getFirst();
        }

        return new SpdxExpression.Or(operands);
    }

    private static SpdxExpression parseAndExpression(TokenCursor cursor) {
        final var operands = new ArrayList<SpdxExpression>();

        do {
            operands.add(parseWithExpression(cursor));
        } while (cursor.matchOperator(SpdxExpressionOperator.AND));

        if (operands.size() == 1) {
            return operands.getFirst();
        }

        return new SpdxExpression.And(operands);
    }

    private static SpdxExpression parseWithExpression(TokenCursor cursor) {
        final SpdxExpression lhs = parseUnaryExpression(cursor);

        if (cursor.matchOperator(SpdxExpressionOperator.WITH)) {
            // Per the SPDX spec, WITH requires a simple license ID (or id+) on
            // the left. The RHS should be an exception ID, but we intentionally
            // accept any expression to handle malformed real-world SBOMs.
            if (!(lhs instanceof SpdxExpression.Identifier)
                    && !(lhs instanceof SpdxExpression.OrLater)) {
                throw new SpdxExpressionParseException(
                        "WITH requires a license ID on the left hand side");
            }
            final SpdxExpression rhs = parseUnaryExpression(cursor);
            return new SpdxExpression.With(lhs, rhs);
        }

        return lhs;
    }

    private static SpdxExpression parseUnaryExpression(TokenCursor cursor) {
        final SpdxExpression expr = parsePrimaryExpression(cursor);

        if (cursor.matchOperator(SpdxExpressionOperator.PLUS)) {
            if (!(expr instanceof SpdxExpression.Identifier id)) {
                throw new SpdxExpressionParseException("'+' can only be applied to a license ID");
            }

            return new SpdxExpression.OrLater(id);
        }

        return expr;
    }

    private static SpdxExpression parsePrimaryExpression(TokenCursor cursor) {
        final SpdxExpressionToken token = cursor.next();

        if (token instanceof Identifier(String id)) {
            return new SpdxExpression.Identifier(id);
        }

        if (token == Grouping.LEFT_PAREN) {
            final SpdxExpression expr = parseOrExpression(cursor);
            cursor.expect(Grouping.RIGHT_PAREN);
            return expr;
        }

        throw new SpdxExpressionParseException(
                "Expected license ID or '(', but got: " + token);
    }

    private static final class TokenCursor {

        private final List<SpdxExpressionToken> tokens;
        private int position;

        private TokenCursor(List<SpdxExpressionToken> tokens) {
            this.tokens = tokens;
        }

        private boolean hasNext() {
            return position < tokens.size();
        }

        private SpdxExpressionToken next() {
            if (!hasNext()) {
                throw new SpdxExpressionParseException("Unexpected end of expression");
            }

            return tokens.get(position++);
        }

        private boolean matchOperator(SpdxExpressionOperator expected) {
            if (hasNext()
                    && tokens.get(position) instanceof Operator(SpdxExpressionOperator operator)
                    && operator == expected) {
                position++;
                return true;
            }

            return false;
        }

        private void expect(SpdxExpressionToken expected) {
            final SpdxExpressionToken token = next();
            if (!token.equals(expected)) {
                throw new SpdxExpressionParseException(
                        "Expected %s, but got: %s".formatted(expected, token));
            }
        }

    }

}
