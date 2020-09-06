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
package org.dependencytrack.policy;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.PolicyCondition;

/**
 * Defines a violation which contains the component and the policy condition
 * that the component violated.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
public class PolicyConditionViolation {

    private final PolicyCondition policyCondition;
    private final Component component;

    public PolicyConditionViolation(PolicyCondition policyCondition, Component component) {
        this.policyCondition = policyCondition;
        this.component = component;
    }

    public PolicyCondition getPolicyCondition() {
        return policyCondition;
    }

    public Component getComponent() {
        return component;
    }
}
