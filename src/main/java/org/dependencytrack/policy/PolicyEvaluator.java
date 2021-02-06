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
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.persistence.QueryManager;
import java.util.List;

/**
 * Defines a PolicyEvaluator. Each PolicyEvaluator should perform a very specific
 * type of check.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
public interface PolicyEvaluator {

    void setQueryManager(final QueryManager qm);

    /**
     * Returns the Subject for which a PolicyEvaluator is capable of analyzing.
     * @return A PolicyCondition Subject
     * @since 4.0.0
     */
    PolicyCondition.Subject supportedSubject();

    /**
     * Performs the evaluation and returns a List of PolicyConditionViolation objects.
     * @param policy the policy to evaluate against
     * @param component the component to evaluate
     * @return a List of zero or more PolicyConditionViolation objects
     * @since 4.0.0
     */
    List<PolicyConditionViolation> evaluate(final Policy policy, final Component component);

}
