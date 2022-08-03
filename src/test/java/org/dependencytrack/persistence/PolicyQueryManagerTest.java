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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class PolicyQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testRemoveProjectFromPolicies() {
        final Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);

        // Create multiple policies that all reference the project
        final Policy policy1 = qm.createPolicy("Test Policy 1", Policy.Operator.ANY, Policy.ViolationState.INFO);
        policy1.setProjects(List.of(project));
        qm.persist(policy1);
        final Policy policy2 = qm.createPolicy("Test Policy 2", Policy.Operator.ANY, Policy.ViolationState.INFO);
        policy2.setProjects(List.of(project));
        qm.persist(policy2);

        // Remove project from all policies and verify that the associations have indeed been cleared
        qm.removeProjectFromPolicies(project);
        assertThat(qm.getObjectById(Policy.class, policy1.getId()).getProjects()).isEmpty();
        assertThat(qm.getObjectById(Policy.class, policy2.getId()).getProjects()).isEmpty();
    }

}