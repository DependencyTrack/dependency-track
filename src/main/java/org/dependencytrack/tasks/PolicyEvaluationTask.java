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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.PolicyEvaluationEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.PolicyEngine;
import java.util.ArrayList;
import java.util.List;

public class PolicyEvaluationTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(PolicyEvaluationTask.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
        if (e instanceof PolicyEvaluationEvent event) {
            if (event.getProject() != null) {
                if (event.getComponents() != null && !event.getComponents().isEmpty()) {
                    performPolicyEvaluation(event.getProject(), event.getComponents());
                } else {
                    performPolicyEvaluation(event.getProject(), new ArrayList<>());
                }
            }
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
