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
package org.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.PolicyEvaluationEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.PolicyEngine;
import org.slf4j.MDC;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

import static org.dependencytrack.common.MdcKeys.MDC_EVENT_TOKEN;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.util.LockUtil.getLockForProjectAndNamespace;

public class PolicyEvaluationTask implements Subscriber {

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
        if (!(e instanceof final PolicyEvaluationEvent event)) {
            return;
        }
        if (event.getProject() == null) {
            return;
        }

        final ReentrantLock lock = getLockForProjectAndNamespace(event.getProject(), getClass().getSimpleName());
        try (var ignoredMdcProjectUuid = MDC.putCloseable(MDC_PROJECT_UUID, event.getProject().getUuid().toString());
             var ignoredMdcProjectName = MDC.putCloseable(MDC_PROJECT_NAME, event.getProject().getName());
             var ignoredMdcProjectVersion = MDC.putCloseable(MDC_PROJECT_VERSION, event.getProject().getVersion());
             var ignoredMdcEventToken = MDC.putCloseable(MDC_EVENT_TOKEN, event.getChainIdentifier().toString())) {
            lock.lock();
            if (event.getComponents() != null && !event.getComponents().isEmpty()) {
                performPolicyEvaluation(event.getProject(), event.getComponents());
            } else {
                performPolicyEvaluation(event.getProject(), new ArrayList<>());
            }
        } finally {
            lock.unlock();
        }
    }

    private void performPolicyEvaluation(Project project, List<Component> components) {
        // Evaluate the components against applicable policies via the PolicyEngine.
        final PolicyEngine pe = new PolicyEngine();
        pe.evaluate(components);
        if (project != null) {
            Event.dispatch(new ProjectMetricsUpdateEvent(project.getUuid()));
        }
    }

}
