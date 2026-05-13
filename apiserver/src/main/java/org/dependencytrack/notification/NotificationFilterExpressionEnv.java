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
package org.dependencytrack.notification;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.cel.common.CelAbstractSyntaxTree;
import dev.cel.common.CelContainer;
import dev.cel.common.CelValidationException;
import dev.cel.common.types.SimpleType;
import dev.cel.compiler.CelCompiler;
import dev.cel.compiler.CelCompilerFactory;
import dev.cel.extensions.CelExtensions;
import dev.cel.parser.CelStandardMacro;
import dev.cel.runtime.CelEvaluationException;
import dev.cel.runtime.CelRuntime;
import dev.cel.runtime.CelRuntimeFactory;
import org.apache.commons.codec.digest.DigestUtils;
import org.dependencytrack.notification.proto.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.BomProcessingFailedSubject;
import org.dependencytrack.notification.proto.v1.BomValidationFailedSubject;
import org.dependencytrack.notification.proto.v1.NewPolicyViolationsSummarySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitiesSummarySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerableDependencySubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.PolicyViolationAnalysisDecisionChangeSubject;
import org.dependencytrack.notification.proto.v1.PolicyViolationSubject;
import org.dependencytrack.notification.proto.v1.UserSubject;
import org.dependencytrack.notification.proto.v1.VexConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.notification.proto.v1.VulnerabilityRetractedSubject;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.concurrent.TimeUnit;

import static org.dependencytrack.cel.CelExpressionUtils.normalizeDurationDays;

/**
 * @since 5.0.0
 */
public final class NotificationFilterExpressionEnv {

    private static final NotificationFilterExpressionEnv INSTANCE = new NotificationFilterExpressionEnv();

    private final Cache<String, CelRuntime.Program> cache;
    private final CelCompiler compiler;
    private final CelRuntime runtime;

    private NotificationFilterExpressionEnv() {
        this.cache = Caffeine.newBuilder()
                .maximumSize(256)
                .expireAfterAccess(1, TimeUnit.HOURS)
                .build();

        this.compiler = CelCompilerFactory.standardCelCompilerBuilder()
                .setStandardMacros(CelStandardMacro.STANDARD_MACROS)
                .addLibraries(CelExtensions.strings())
                .setContainer(CelContainer.ofName("org.dependencytrack.notification.v1"))
                .addVar("level", SimpleType.INT)
                .addVar("scope", SimpleType.INT)
                .addVar("group", SimpleType.INT)
                .addVar("title", SimpleType.STRING)
                .addVar("content", SimpleType.STRING)
                .addVar("timestamp", SimpleType.TIMESTAMP)
                .addVar("subject", SimpleType.DYN)
                .addMessageTypes(
                        Notification.getDescriptor(),
                        BomConsumedOrProcessedSubject.getDescriptor(),
                        BomProcessingFailedSubject.getDescriptor(),
                        BomValidationFailedSubject.getDescriptor(),
                        NewPolicyViolationsSummarySubject.getDescriptor(),
                        NewVulnerabilitiesSummarySubject.getDescriptor(),
                        NewVulnerabilitySubject.getDescriptor(),
                        NewVulnerableDependencySubject.getDescriptor(),
                        PolicyViolationSubject.getDescriptor(),
                        PolicyViolationAnalysisDecisionChangeSubject.getDescriptor(),
                        VulnerabilityAnalysisDecisionChangeSubject.getDescriptor(),
                        VexConsumedOrProcessedSubject.getDescriptor(),
                        VulnerabilityRetractedSubject.getDescriptor(),
                        UserSubject.getDescriptor())
                .build();

        this.runtime = CelRuntimeFactory.standardCelRuntimeBuilder()
                .addLibraries(CelExtensions.strings())
                .addMessageTypes(
                        Notification.getDescriptor(),
                        BomConsumedOrProcessedSubject.getDescriptor(),
                        BomProcessingFailedSubject.getDescriptor(),
                        BomValidationFailedSubject.getDescriptor(),
                        NewPolicyViolationsSummarySubject.getDescriptor(),
                        NewVulnerabilitiesSummarySubject.getDescriptor(),
                        NewVulnerabilitySubject.getDescriptor(),
                        NewVulnerableDependencySubject.getDescriptor(),
                        PolicyViolationSubject.getDescriptor(),
                        PolicyViolationAnalysisDecisionChangeSubject.getDescriptor(),
                        VulnerabilityAnalysisDecisionChangeSubject.getDescriptor(),
                        VexConsumedOrProcessedSubject.getDescriptor(),
                        VulnerabilityRetractedSubject.getDescriptor(),
                        UserSubject.getDescriptor())
                .build();
    }

    public static NotificationFilterExpressionEnv getInstance() {
        return INSTANCE;
    }

    public CelRuntime.Program compile(String expressionSrc) {
        final String normalizedSrc = normalizeDurationDays(expressionSrc);
        return cache.get(DigestUtils.sha256Hex(normalizedSrc), key -> {
            final CelAbstractSyntaxTree ast;
            try {
                ast = compiler.compile(normalizedSrc).getAst();
            } catch (CelValidationException e) {
                throw new InvalidNotificationFilterExpressionException(
                        "Failed to compile expression",
                        e.getErrors());
            }

            try {
                return runtime.createProgram(ast);
            } catch (CelEvaluationException e) {
                throw new InvalidNotificationFilterExpressionException(
                        "Failed to create program",
                        e.getMessage());
            }
        });
    }

    public boolean evaluate(
            CelRuntime.Program program,
            Notification notification,
            @Nullable Object subject) throws CelEvaluationException {
        final var args = new HashMap<String, @Nullable Object>(7);
        args.put("level", notification.getLevelValue());
        args.put("scope", notification.getScopeValue());
        args.put("group", notification.getGroupValue());
        args.put("title", notification.getTitle());
        args.put("content", notification.getContent());
        args.put("timestamp", notification.getTimestamp());
        args.put("subject", subject);

        return (Boolean) program.eval(args);
    }

}
