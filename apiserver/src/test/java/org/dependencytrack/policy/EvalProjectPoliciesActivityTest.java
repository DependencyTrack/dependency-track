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

import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EvalProjectPoliciesActivityTest {

    @Test
    void passesActivityHeartbeatToPolicyEngine() {
        final UUID projectUuid = UUID.randomUUID();
        final var heartbeatInvoked = new AtomicBoolean();
        final ActivityContext activityContext = mock(ActivityContext.class);
        when(activityContext.maybeHeartbeat()).thenAnswer(_ -> {
            heartbeatInvoked.set(true);
            return true;
        });

        final CelPolicyEngine policyEngine = mock(CelPolicyEngine.class);
        doAnswer(invocation -> {
            final Runnable heartbeat = invocation.getArgument(1);
            heartbeat.run();
            return null;
        }).when(policyEngine).evaluateProject(eq(projectUuid), any());

        final var activity = new EvalProjectPoliciesActivity(policyEngine);
        final var arg = EvalProjectPoliciesArg.newBuilder()
                .setProjectUuid(projectUuid.toString())
                .build();

        assertThatNoException().isThrownBy(() -> activity.execute(activityContext, arg));
        verify(policyEngine).evaluateProject(eq(projectUuid), any(Runnable.class));
        assertThat(heartbeatInvoked).isTrue();
    }

}
