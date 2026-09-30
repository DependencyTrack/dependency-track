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
package org.dependencytrack.auth.workloadidentity;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Struct;
import com.google.protobuf.util.JsonFormat;
import dev.cel.common.CelAbstractSyntaxTree;
import dev.cel.common.CelOptions;
import dev.cel.common.CelValidationException;
import dev.cel.common.types.MapType;
import dev.cel.common.types.SimpleType;
import dev.cel.compiler.CelCompiler;
import dev.cel.compiler.CelCompilerFactory;
import dev.cel.extensions.CelExtensions;
import dev.cel.parser.CelStandardMacro;
import dev.cel.runtime.CelEvaluationException;
import dev.cel.runtime.CelRuntime;
import dev.cel.runtime.CelRuntimeFactory;
import org.apache.commons.codec.digest.DigestUtils;
import org.dependencytrack.cel.InvalidCelExpressionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

import static java.util.Objects.requireNonNullElse;

/// @since 5.2.0
public final class WorkloadIdentityConditionEnv {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkloadIdentityConditionEnv.class);
    private static final WorkloadIdentityConditionEnv INSTANCE = new WorkloadIdentityConditionEnv();

    private final Cache<String, CelRuntime.Program> cache;
    private final CelCompiler compiler;
    private final CelRuntime runtime;

    private WorkloadIdentityConditionEnv() {
        this.cache = Caffeine.newBuilder()
                .maximumSize(256)
                .expireAfterAccess(1, TimeUnit.HOURS)
                .build();

        final CelOptions options = CelOptions.current()
                // JSON numbers are doubles, which conditions compare against integer literals such as timestamps.
                .enableHeterogeneousNumericComparisons(true)
                .build();

        this.compiler = CelCompilerFactory.standardCelCompilerBuilder()
                .setOptions(options)
                .setStandardMacros(CelStandardMacro.STANDARD_MACROS)
                .addLibraries(CelExtensions.strings())
                .addVar("claims", MapType.create(SimpleType.STRING, SimpleType.DYN))
                .setResultType(SimpleType.BOOL)
                .build();

        this.runtime = CelRuntimeFactory.standardCelRuntimeBuilder()
                .setOptions(options)
                .addLibraries(CelExtensions.strings())
                .build();
    }

    public static WorkloadIdentityConditionEnv getInstance() {
        return INSTANCE;
    }

    public Predicate<String> matcher(String claimsJson) {
        final var claims = Struct.newBuilder();
        try {
            JsonFormat.parser().merge(claimsJson, claims);
        } catch (InvalidProtocolBufferException e) {
            LOGGER.debug("Failed to parse JSON claims into Protobuf struct", e);
            return _ -> false;
        }

        final Map<String, Object> variables = Map.of("claims", claims.build());
        return condition -> {
            try {
                return compile(condition).eval(variables) instanceof Boolean result && result;
            } catch (CelEvaluationException e) {
                LOGGER.debug("Failed to evaluate condition {}", condition, e);
                return false;
            } catch (InvalidCelExpressionException e) {
                LOGGER.warn("Failed to compile condition {}", condition, e);
                return false;
            }
        };
    }

    public CelRuntime.Program compile(String condition) {
        return cache.get(DigestUtils.sha256Hex(condition), ignored -> {
            final CelAbstractSyntaxTree ast;
            try {
                ast = compiler.compile(condition).getAst();
            } catch (CelValidationException e) {
                throw new InvalidCelExpressionException("Condition is invalid.", e);
            }

            // Claim values are dynamic, so the type checker accepts an expression such as
            // claims.admin where a boolean is expected. Demand an explicit comparison instead.
            if (!SimpleType.BOOL.equals(ast.getResultType())) {
                throw new InvalidCelExpressionException(
                        "Condition is invalid.",
                        List.of(new InvalidCelExpressionException.Error(
                                1,
                                0,
                                "Condition must return a boolean, but returns %s"
                                        .formatted(ast.getResultType().name()))));
            }

            try {
                return runtime.createProgram(ast);
            } catch (CelEvaluationException e) {
                throw new InvalidCelExpressionException(
                        "Condition is invalid.",
                        List.of(new InvalidCelExpressionException.Error(
                                1,
                                0,
                                requireNonNullElse(e.getMessage(), e.getClass().getName()))));
            }
        });
    }
}
