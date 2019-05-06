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
import java.util.UUID;

public class EvidenceTest { 

    @Test
    public void testId() {
        Evidence evidence = new Evidence();
        evidence.setId(111L);
        Assert.assertEquals(111L, evidence.getId());
    } 

    @Test
    public void testType() {
        Evidence evidence = new Evidence();
        evidence.setType("my-type");
        Assert.assertEquals("my-type", evidence.getType());
    } 

    @Test
    public void testConfidence() {
        Evidence evidence = new Evidence();
        evidence.setConfidence(3);
        Assert.assertEquals(3, evidence.getConfidence());
    } 

    @Test
    public void testSource() {
        Evidence evidence = new Evidence();
        evidence.setSource("my-source");
        Assert.assertEquals("my-source", evidence.getSource());
    } 

    @Test
    public void testName() {
        Evidence evidence = new Evidence();
        evidence.setName("my-name");
        Assert.assertEquals("my-name", evidence.getName());
    } 

    @Test
    public void testValue() {
        Evidence evidence = new Evidence();
        evidence.setValue("my-value");
        Assert.assertEquals("my-value", evidence.getValue());
    } 

    @Test
    public void testComponent() {
        Component component = new Component();
        Evidence evidence = new Evidence();
        evidence.setComponent(component);
        Assert.assertEquals(component, evidence.getComponent());
    } 

    @Test
    public void testUuid() {
        UUID uuid = UUID.randomUUID();
        Evidence evidence = new Evidence();
        evidence.setUuid(uuid);
        Assert.assertEquals(uuid.toString(), evidence.getUuid().toString());
    } 
}
