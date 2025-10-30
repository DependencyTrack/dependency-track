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
package org.dependencytrack.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

class PolicyTest {

    @Test
    void testId() {
        Policy policy = new Policy();
        policy.setId(111L);
        Assertions.assertEquals(111L, policy.getId());
    }

    @Test
    void testName() {
        Policy policy = new Policy();
        policy.setName("Banned Components");
        Assertions.assertEquals("Banned Components", policy.getName());
    }

    @Test
    void testOperator() {
        Policy policy = new Policy();
        policy.setOperator(Policy.Operator.ALL);
        Assertions.assertEquals("ALL", policy.getOperator().name());
    }

    @Test
    void testViolationState() {
        Policy policy = new Policy();
        policy.setViolationState(Policy.ViolationState.WARN);
        Assertions.assertEquals("WARN", policy.getViolationState().name());
    }

    @Test
    void testPolicyConditions() {
        List<PolicyCondition> conditions = new ArrayList<>();
        PolicyCondition condition = new PolicyCondition();
        conditions.add(condition);
        Policy policy = new Policy();
        policy.setPolicyConditions(conditions);
        Assertions.assertEquals(1, policy.getPolicyConditions().size());
        Assertions.assertEquals(condition, policy.getPolicyConditions().get(0));
    }

    @Test
    void testProjects() {
        List<Project> projects = new ArrayList<>();
        Project project = new Project();
        projects.add(project);
        Policy policy = new Policy();
        policy.setProjects(projects);
        Assertions.assertEquals(1, policy.getProjects().size());
        Assertions.assertEquals(project, policy.getProjects().get(0));
    }

    @Test
    void testTags() {
        Set<Tag> tags = new HashSet<>();
        Tag tag = new Tag();
        tags.add(tag);
        Policy policy = new Policy();
        policy.setTags(tags);
        Assertions.assertEquals(1, policy.getTags().size());
        Assertions.assertEquals(tag, policy.getTags().iterator().next());
    }

    @Test
    void testIncludeChildren() {
        Policy policy = new Policy();
        Assertions.assertFalse(policy.isIncludeChildren());
        policy.setIncludeChildren(true);
        Assertions.assertTrue(policy.isIncludeChildren());
    }
}
