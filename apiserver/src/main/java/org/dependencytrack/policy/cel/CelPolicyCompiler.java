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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.cel.common.CelAbstractSyntaxTree;
import dev.cel.common.CelIssue;
import dev.cel.common.CelSource;
import dev.cel.common.CelSourceLocation;
import dev.cel.common.CelValidationException;
import dev.cel.common.types.CelType;
import dev.cel.runtime.CelEvaluationException;
import dev.cel.runtime.CelRuntime;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections4.MultiValuedMap;
import org.dependencytrack.policy.cel.CelPolicyAstAnalyzer.FunctionSignature;
import org.dependencytrack.policy.cel.CelPolicySpdxExpressionValidator.SpdxExpressionValidationError;
import org.dependencytrack.policy.cel.CelPolicyVersValidator.VersValidationError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.dependencytrack.cel.CelExpressionUtils.normalizeDurationDays;
import static org.dependencytrack.policy.cel.CelPolicyRequirements.FIELD_EXPANSIONS;
import static org.dependencytrack.policy.cel.CelPolicyRequirements.FUNCTION_FIELD_REQUIREMENTS;

public final class CelPolicyCompiler {

    public enum CacheMode {
        CACHE,
        NO_CACHE
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(CelPolicyCompiler.class);
    private static final ConcurrentHashMap<CelPolicyType, CelPolicyCompiler> INSTANCES = new ConcurrentHashMap<>();
    private final Cache<String, CelPolicyProgram> cache;
    private final CelPolicyType policyType;

    public CelPolicyCompiler(CelPolicyType policyType) {
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(60, TimeUnit.MINUTES)
                .maximumSize(1000)
                .build();
        this.policyType = policyType;
    }

    public static CelPolicyCompiler getInstance(CelPolicyType policyType) {
        return INSTANCES.computeIfAbsent(policyType, CelPolicyCompiler::new);
    }

    /**
     * Compile, type-check, and analyze a given CEL expression.
     *
     * @param scriptSrc Source of the expression to compile
     * @param cacheMode Whether the {@link CelPolicyProgram} shall be cached upon successful compilation
     * @return The compiled {@link CelPolicyProgram}
     * @throws CelValidationException When compilation, type checking, or analysis failed
     */
    public CelPolicyProgram compile(String scriptSrc, CacheMode cacheMode) throws CelValidationException {
        final String normalizedSrc = normalizeDurationDays(scriptSrc);
        final String scriptDigest = DigestUtils.sha256Hex(normalizedSrc);

        if (cacheMode == CacheMode.CACHE) {
            final CelPolicyProgram cached = cache.getIfPresent(scriptDigest);
            if (cached != null) {
                return cached;
            }
        }

        LOGGER.debug("Compiling expression: %s".formatted(normalizedSrc));
        final CelAbstractSyntaxTree ast = policyType.compiler().compile(normalizedSrc).getAst();

        final CelRuntime.Program celProgram;
        try {
            celProgram = policyType.runtime().createProgram(ast);
        } catch (CelEvaluationException e) {
            throw new CelValidationException(ast.getSource(),
                    List.of(CelIssue.formatError(0, 0, e.getMessage())));
        }

        final var analysis = analyze(ast);
        final Set<String> usedFunctions = analysis.usedFunctions();
        validateVersRanges(ast, usedFunctions);
        validateSpdxExpressions(ast, usedFunctions);

        final var program = new CelPolicyProgram(celProgram, analysis.requirements());
        if (cacheMode == CacheMode.CACHE) {
            cache.put(scriptDigest, program);
        }
        
        return program;
    }

    private record AnalysisResult(MultiValuedMap<CelType, String> requirements, Set<String> usedFunctions) {
    }

    private static AnalysisResult analyze(CelAbstractSyntaxTree ast) {
        final var visitor = new CelPolicyAstAnalyzer(ast);
        visitor.analyze();

        final MultiValuedMap<CelType, String> requirements = visitor.getAccessedFieldsByType();

        for (final var expansion : FIELD_EXPANSIONS.entrySet()) {
            final CelType type = expansion.getKey();
            if (!requirements.containsKey(type)) {
                continue;
            }

            for (final var fieldExpansion : expansion.getValue().entrySet()) {
                if (requirements.get(type).contains(fieldExpansion.getKey())) {
                    requirements.putAll(type, fieldExpansion.getValue());
                }
            }
        }

        final Set<FunctionSignature> functionSignatures = visitor.getUsedFunctionSignatures();
        for (final FunctionSignature funcSignature : functionSignatures) {
            final Map<CelType, List<String>> funcRequirements =
                    FUNCTION_FIELD_REQUIREMENTS.get(funcSignature.function());
            if (funcRequirements == null) {
                continue;
            }

            final List<String> fields = funcRequirements.get(funcSignature.targetType());
            if (fields != null) {
                requirements.putAll(funcSignature.targetType(), fields);
            }
        }

        final Set<String> usedFunctions = functionSignatures.stream()
                .map(FunctionSignature::function)
                .collect(Collectors.toSet());

        return new AnalysisResult(requirements, usedFunctions);
    }

    private static void validateVersRanges(
            CelAbstractSyntaxTree ast,
            Set<String> usedFunctions) throws CelValidationException {
        final var visitor = new CelPolicyVersValidator(ast, usedFunctions);
        visitor.validate();

        final List<VersValidationError> validationErrors = visitor.getErrors();
        if (validationErrors.isEmpty()) {
            return;
        }

        final CelSource source = ast.getSource();
        final List<CelIssue> issues = validationErrors.stream()
                .map(versError -> {
                    final int position = versError.position() != null ? versError.position() : 0;
                    final var location = source.getOffsetLocation(position);
                    return CelIssue.formatError(
                            location.map(CelSourceLocation::getLine).orElse(0),
                            location.map(CelSourceLocation::getColumn).orElse(0),
                            versError.exception().getMessage());
                })
                .toList();

        throw new CelValidationException(source, issues);
    }

    private static void validateSpdxExpressions(
            CelAbstractSyntaxTree ast,
            Set<String> usedFunctions) throws CelValidationException {
        final var visitor = new CelPolicySpdxExpressionValidator(ast, usedFunctions);
        visitor.validate();

        final List<SpdxExpressionValidationError> validationErrors = visitor.getErrors();
        if (validationErrors.isEmpty()) {
            return;
        }

        final CelSource source = ast.getSource();
        final List<CelIssue> issues = validationErrors.stream()
                .map(spdxError -> {
                    final int position = spdxError.position() != null ? spdxError.position() : 0;
                    final var location = source.getOffsetLocation(position);
                    return CelIssue.formatError(
                            location.map(CelSourceLocation::getLine).orElse(0),
                            location.map(CelSourceLocation::getColumn).orElse(0),
                            spdxError.message());
                })
                .toList();

        throw new CelValidationException(source, issues);
    }

}
