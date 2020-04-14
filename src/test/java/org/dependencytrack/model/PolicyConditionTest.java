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

public class PolicyConditionTest {

    @Test
    public void testId() {
        PolicyCondition pc = new PolicyCondition();
        pc.setId(111L);
        Assert.assertEquals(111L, pc.getId());
    }

    @Test
    public void testPolicy() {
        Policy policy = new Policy();
        PolicyCondition pc = new PolicyCondition();
        pc.setPolicy(policy);
        Assert.assertEquals(policy, pc.getPolicy());
    }

    @Test
    public void testOperator() {
        PolicyCondition pc = new PolicyCondition();
        pc.setOperator(PolicyCondition.Operator.NUMERIC_EQUAL);
        Assert.assertEquals("NUMERIC_EQUAL", pc.getOperator().name());
    }

    @Test
    public void testSubject() {
        PolicyCondition pc = new PolicyCondition();
        pc.setSubject(PolicyCondition.Subject.LICENSE_GROUP);
        Assert.assertEquals("LICENSE_GROUP", pc.getSubject().name());
    }

    @Test
    public void testValue() {
        PolicyCondition pc = new PolicyCondition();
        pc.setValue("Test Value");
        Assert.assertEquals("Test Value", pc.getValue());
    }
}
