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
package org.dependencytrack.model;

import org.junit.Assert;
import org.junit.Test;
import java.util.ArrayList;
import java.util.List;

public class PolicyTest {

    @Test
    public void testId() {
        Policy policy = new Policy();
        policy.setId(111L);
        Assert.assertEquals(111L, policy.getId());
    }

    @Test
    public void testName() {
        Policy policy = new Policy();
        policy.setName("Banned Components");
        Assert.assertEquals("Banned Components", policy.getName());
    }

    @Test
    public void testOperator() {
        Policy policy = new Policy();
        policy.setOperator(Policy.Operator.ALL);
        Assert.assertEquals("ALL", policy.getOperator().name());
    }

    @Test
    public void testViolationState() {
        Policy policy = new Policy();
        policy.setViolationState(Policy.ViolationState.WARN);
        Assert.assertEquals("WARN", policy.getViolationState().name());
    }

    @Test
    public void testPolicyConditions() {
        List<PolicyCondition> conditions = new ArrayList<>();
        PolicyCondition condition = new PolicyCondition();
        conditions.add(condition);
        Policy policy = new Policy();
        policy.setPolicyConditions(conditions);
        Assert.assertEquals(1, policy.getPolicyConditions().size());
        Assert.assertEquals(condition, policy.getPolicyConditions().get(0));
    }

    @Test
    public void testProjects() {
        List<Project> projects = new ArrayList<>();
        Project project = new Project();
        projects.add(project);
        Policy policy = new Policy();
        policy.setProjects(projects);
        Assert.assertEquals(1, policy.getProjects().size());
        Assert.assertEquals(project, policy.getProjects().get(0));
    }
}
