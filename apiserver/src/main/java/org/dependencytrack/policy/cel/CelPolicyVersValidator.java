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
package org.dependencytrack.policy.cel;

import dev.cel.common.CelAbstractSyntaxTree;
import dev.cel.common.ast.CelConstant;
import dev.cel.common.ast.CelExpr;
import dev.cel.common.navigation.CelNavigableAst;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import org.dependencytrack.proto.policy.v1.Component;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.DEPENDS_ON;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.IS_DEPENDENCY_OF;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.IS_DIRECT_DEPENDENCY_OF;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.IS_EXCLUSIVE_DEPENDENCY_OF;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.MATCHES_RANGE;

final class CelPolicyVersValidator {

    private static final Set<String> COMPONENT_FILTER_FIELDS = Set.of("group", "name", "cpe", "purl", "swid_tag_id");
    private static final List<String> COMPONENT_FILTER_FIELDS_SORTED = COMPONENT_FILTER_FIELDS.stream().sorted().toList();

    static final Set<String> RELEVANT_FUNCTIONS = Set.of(
            MATCHES_RANGE.functionName(),
            DEPENDS_ON.functionName(),
            IS_DEPENDENCY_OF.functionName(),
            IS_EXCLUSIVE_DEPENDENCY_OF.functionName(),
            IS_DIRECT_DEPENDENCY_OF.functionName());

    record VersValidationError(RuntimeException exception, @Nullable Integer position) {
    }

    private final CelAbstractSyntaxTree ast;
    private final Map<Long, Integer> positions;
    private final List<VersValidationError> errors;
    private final boolean isApplicable;

    CelPolicyVersValidator(CelAbstractSyntaxTree ast, Set<String> usedFunctions) {
        this.ast = ast;
        this.positions = ast.getSource().getPositionsMap();
        this.errors = new ArrayList<>();
        this.isApplicable = usedFunctions.stream().anyMatch(RELEVANT_FUNCTIONS::contains);
    }

    void validate() {
        if (!isApplicable) {
            return;
        }

        CelNavigableAst.fromAst(ast).getRoot().allNodes()
                .filter(node -> node.getKind() == CelExpr.ExprKind.Kind.CALL)
                .forEach(node -> {
                    final CelExpr expr = node.expr();
                    final CelExpr.CelCall callExpr = expr.call();
                    final String functionName = callExpr.function();

                    if (MATCHES_RANGE.functionName().equals(functionName)) {
                        if (!callExpr.args().isEmpty()) {
                            maybeValidateVers(callExpr.args().getFirst());
                        }
                    } else if ((DEPENDS_ON.functionName().equals(functionName)
                            || IS_DEPENDENCY_OF.functionName().equals(functionName)
                            || IS_EXCLUSIVE_DEPENDENCY_OF.functionName().equals(functionName)
                            || IS_DIRECT_DEPENDENCY_OF.functionName().equals(functionName))
                            && callExpr.args().size() == 1) {
                        maybeValidateComponentStruct(callExpr.args().getFirst());
                    }
                });
    }

    private void maybeValidateComponentStruct(final CelExpr expr) {
        if (expr.exprKind().getKind() != CelExpr.ExprKind.Kind.STRUCT) {
            return;
        }

        final CelExpr.CelStruct structExpr = expr.struct();
        final String fullName = Component.getDescriptor().getFullName();
        if (!fullName.equals(structExpr.messageName()) && !fullName.endsWith("." + structExpr.messageName())) {
            return;
        }

        CelExpr.CelStruct.Entry versionEntry = null;
        boolean hasQualifiers = false;
        for (final CelExpr.CelStruct.Entry entry : structExpr.entries()) {
            if ("version".equals(entry.fieldKey())) {
                versionEntry = entry;
            } else if (COMPONENT_FILTER_FIELDS.contains(entry.fieldKey())) {
                hasQualifiers = true;
            }
        }
        if (versionEntry == null) {
            return;
        }

        final CelExpr valueExpr = versionEntry.value();
        if (valueExpr.exprKind().getKind() != CelExpr.ExprKind.Kind.CONSTANT) {
            return;
        }
        final String version = valueExpr.constant().stringValue();
        if (!version.startsWith("vers:")) {
            return;
        }

        if (!hasQualifiers) {
            final var exception = new RuntimeException("""
                    Querying by version range without providing an additional field to filter on is not allowed. \
                    Possible fields to filter on are: %s""".formatted(COMPONENT_FILTER_FIELDS_SORTED));
            errors.add(new VersValidationError(exception, positions.get(expr.id())));
        }

        maybeValidateVers(valueExpr);
    }

    private void maybeValidateVers(final CelExpr expr) {
        if (expr.exprKind().getKind() != CelExpr.ExprKind.Kind.CONSTANT) {
            return;
        }

        final CelConstant constExpr = expr.constant();
        if (constExpr.getKind() != CelConstant.Kind.STRING_VALUE) {
            return;
        }

        try {
            final Vers vers = Vers.parse(constExpr.stringValue());
            vers.validate();
        } catch (VersException e) {
            errors.add(new VersValidationError(e, positions.get(expr.id())));
        }
    }

    List<VersValidationError> getErrors() {
        return Collections.unmodifiableList(errors);
    }

}
