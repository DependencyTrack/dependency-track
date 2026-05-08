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
package org.dependencytrack.policy;

import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;

import java.util.UUID;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;

/**
 * @since 5.0.0
 */
@ActivitySpec(name = "eval-project-policies", defaultTaskQueue = "policy-evaluations")
public final class EvalProjectPoliciesActivity implements Activity<EvalProjectPoliciesArg, Void> {

    private final CelPolicyEngine policyEngine;

    public EvalProjectPoliciesActivity(CelPolicyEngine policyEngine) {
        this.policyEngine = policyEngine;
    }

    @Override
    public @Nullable Void execute(ActivityContext ctx, @Nullable EvalProjectPoliciesArg argument) throws Exception {
        if (argument == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        try (var ignored = MDC.putCloseable(MDC_PROJECT_UUID, argument.getProjectUuid())) {
            policyEngine.evaluateProject(UUID.fromString(argument.getProjectUuid()));
        }

        return null;
    }

}
