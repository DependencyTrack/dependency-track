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
import dev.cel.common.ast.CelExpr;
import dev.cel.common.navigation.CelNavigableAst;
import dev.cel.common.types.CelType;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.jspecify.annotations.Nullable;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class CelPolicyAstAnalyzer {

    record FunctionSignature(String function, @Nullable CelType targetType, List<@Nullable CelType> argumentTypes) {
    }

    private final CelAbstractSyntaxTree ast;
    private final MultiValuedMap<CelType, String> accessedFieldsByType;
    private final Set<FunctionSignature> usedFunctionSignatures;

    CelPolicyAstAnalyzer(CelAbstractSyntaxTree ast) {
        this.ast = ast;
        this.accessedFieldsByType = new HashSetValuedHashMap<>();
        this.usedFunctionSignatures = new HashSet<>();
    }

    void analyze() {
        CelNavigableAst.fromAst(ast).getRoot().allNodes()
                .forEach(node -> {
                    final CelExpr expr = node.expr();
                    switch (expr.exprKind().getKind()) {
                        case SELECT -> visitSelect(expr);
                        case CALL -> visitCall(expr);
                        default -> {
                        }
                    }
                });
    }

    private void visitSelect(CelExpr expr) {
        final CelExpr.CelSelect selectExpr = expr.select();
        final @Nullable CelType operandType = ast.getType(selectExpr.operand().id()).orElse(null);
        if (operandType != null) {
            accessedFieldsByType.put(operandType, selectExpr.field());
        }
    }

    private void visitCall(CelExpr expr) {
        final CelExpr.CelCall callExpr = expr.call();

        final @Nullable CelType targetType = callExpr.target()
                .flatMap(target -> ast.getType(target.id()))
                .orElse(null);

        final List<@Nullable CelType> argumentTypes = callExpr.args().stream()
                .map(arg -> ast.getType(arg.id()).orElse(null))
                .toList();

        usedFunctionSignatures.add(new FunctionSignature(callExpr.function(), targetType, argumentTypes));
    }

    MultiValuedMap<CelType, String> getAccessedFieldsByType() {
        return this.accessedFieldsByType;
    }

    Set<FunctionSignature> getUsedFunctionSignatures() {
        return this.usedFunctionSignatures;
    }

}
