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

import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class EvalProjectPoliciesActivityTest {

    @Test
    void softFailsWhenPolicyEvaluationTimesOut() {
        final UUID projectUuid = UUID.randomUUID();
        final CelPolicyEngine policyEngine = mock(CelPolicyEngine.class);
        doThrow(new PolicyEvaluationTimedOutException(Duration.ofHours(1)))
                .when(policyEngine)
                .evaluateProject(eq(projectUuid), any());

        final var activity = new EvalProjectPoliciesActivity(policyEngine, Duration.ofHours(1));
        final var arg = EvalProjectPoliciesArg.newBuilder()
                .setProjectUuid(projectUuid.toString())
                .build();

        assertThatNoException().isThrownBy(() -> activity.execute(mock(ActivityContext.class), arg));
        verify(policyEngine).evaluateProject(eq(projectUuid), any());
    }

    @Test
    void passesDeadlineWrappedHeartbeatToPolicyEngine() {
        final UUID projectUuid = UUID.randomUUID();
        final CelPolicyEngine policyEngine = mock(CelPolicyEngine.class);
        doAnswer(_ -> null)
                .when(policyEngine)
                .evaluateProject(eq(projectUuid), any());

        final var activity = new EvalProjectPoliciesActivity(policyEngine, Duration.ofMinutes(30));
        final var arg = EvalProjectPoliciesArg.newBuilder()
                .setProjectUuid(projectUuid.toString())
                .build();

        assertThatNoException().isThrownBy(() -> activity.execute(mock(ActivityContext.class), arg));
        verify(policyEngine).evaluateProject(eq(projectUuid), any(Runnable.class));
    }

}
