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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * @since 5.0.0
 */
public final class SpdxExpressions {

    private SpdxExpressions() {
    }

    public static boolean allows(String expression, List<String> ids) {
        final SpdxExpression parsed = SpdxExpressionParser.getInstance().tryParse(expression);
        if (parsed == null) {
            return false;
        }

        return allows(parsed, buildAllowsMatcher(ids));
    }

    public static boolean requiresAny(String expression, List<String> ids) {
        final SpdxExpression parsed = SpdxExpressionParser.getInstance().tryParse(expression);
        if (parsed == null) {
            return false;
        }

        return requires(parsed, buildRequiresMatcher(ids));
    }

    private static Predicate<SpdxExpression> buildAllowsMatcher(List<String> ids) {
        final List<SpdxLicenseId> leafEntries = new ArrayList<>();
        final List<SpdxExpression.With> withCompounds = new ArrayList<>();

        for (final String id : ids) {
            final SpdxExpression parsed = SpdxExpressionParser.getInstance().tryParse(id);
            if (parsed == null) {
                leafEntries.add(SpdxLicenseId.of(id));
                continue;
            }

            final SpdxLicenseId licenseId = SpdxLicenseId.of(parsed);
            if (licenseId != null) {
                leafEntries.add(licenseId);
            } else if (parsed instanceof SpdxExpression.With with) {
                withCompounds.add(with);
            }
        }

        return expr -> {
            final SpdxLicenseId exprId = SpdxLicenseId.of(expr);

            if (exprId != null) {
                return leafEntries.stream().anyMatch(exprId::isCompatibleWith);
            }

            if (expr instanceof SpdxExpression.With with) {
                return withCompounds.stream().anyMatch(
                        allowed -> withCompoundMatches(with, allowed));
            }

            return false;
        };
    }

    private static Predicate<SpdxExpression> buildRequiresMatcher(List<String> ids) {
        final List<SpdxLicenseId> leafEntries = new ArrayList<>();
        final List<SpdxExpression.With> withCompounds = new ArrayList<>();

        for (final String id : ids) {
            final SpdxExpression parsed = SpdxExpressionParser.getInstance().tryParse(id);
            if (parsed == null) {
                leafEntries.add(SpdxLicenseId.of(id));
                continue;
            }

            final SpdxLicenseId licenseId = SpdxLicenseId.of(parsed);
            if (licenseId != null) {
                leafEntries.add(licenseId);
            } else if (parsed instanceof SpdxExpression.With with) {
                withCompounds.add(with);
            }
        }

        return expr -> {
            final SpdxLicenseId exprId = SpdxLicenseId.of(expr);
            if (exprId != null) {
                return leafEntries.stream().anyMatch(exprId::isEquivalentTo);
            }

            if (expr instanceof SpdxExpression.With with) {
                return withCompounds.stream().anyMatch(
                        allowed -> withCompoundMatches(with, allowed));
            }

            return false;
        };
    }

    private static boolean withCompoundMatches(SpdxExpression.With expr, SpdxExpression.With allowed) {
        final SpdxLicenseId exprLicense = SpdxLicenseId.of(expr.license());
        final SpdxLicenseId allowedLicense = SpdxLicenseId.of(allowed.license());

        if (exprLicense == null || allowedLicense == null) {
            return false;
        }

        if (!(expr.exception() instanceof SpdxExpression.Identifier exprException)
                || !(allowed.exception() instanceof SpdxExpression.Identifier allowedException)) {
            return false;
        }

        return exprLicense.isCompatibleWith(allowedLicense)
                && exprException.id().equalsIgnoreCase(allowedException.id());
    }

    private static boolean allows(SpdxExpression expr, Predicate<SpdxExpression> isAllowed) {
        return switch (expr) {
            case SpdxExpression.Identifier id -> isAllowed.test(id);
            // WITH and OrLater are atomic compounds. Match the whole node, not children.
            case SpdxExpression.With with -> isAllowed.test(with);
            case SpdxExpression.OrLater orLater -> isAllowed.test(orLater);
            case SpdxExpression.Or or -> or.operands().stream().anyMatch(arg -> allows(arg, isAllowed));
            // AND: all children must be satisfiable.
            case SpdxExpression.And and -> and.operands().stream().allMatch(arg -> allows(arg, isAllowed));
        };
    }

    private static boolean requires(SpdxExpression expr, Predicate<SpdxExpression> isRequired) {
        return switch (expr) {
            case SpdxExpression.Identifier id -> isRequired.test(id);
            // WITH is an atomic compound, meaning the whole license-with-exception is the obligation.
            case SpdxExpression.With with -> isRequired.test(with);
            // OrLater(X) means "X or any later version". Only the base version X is guaranteed,
            // so check whether the base license is required.
            case SpdxExpression.OrLater orLater -> requires(orLater.license(), isRequired);
            case SpdxExpression.Or or -> or.operands().stream().allMatch(arg -> requires(arg, isRequired));
            // AND: required if any child requires it.
            case SpdxExpression.And and -> and.operands().stream().anyMatch(arg -> requires(arg, isRequired));
        };
    }

}
