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

import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.persistence.QueryManager;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Reusable methods that PolicyEvaluator implementations can extend.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
public abstract class AbstractPolicyEvaluator implements PolicyEvaluator {

    protected QueryManager qm = new QueryManager();

    public void setQueryManager(final QueryManager qm) {
        this.qm = qm;
    }

    protected List<PolicyCondition> extractSupportedConditions(final Policy policy) {
        if (policy == null || policy.getPolicyConditions() == null) {
            return new ArrayList<>();
        } else {
            return policy.getPolicyConditions().stream()
                    .filter(p -> supportedSubject() == p.getSubject())
                    .collect(Collectors.toList());
        }
    }

}
