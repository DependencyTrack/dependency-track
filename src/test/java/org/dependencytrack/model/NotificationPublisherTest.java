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

public class NotificationPublisherTest { 

    @Test
    public void testId() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setId(111L);
        Assert.assertEquals(111L, publisher.getId());
    } 

    @Test
    public void testName() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setName("My Publisher");
        Assert.assertEquals("My Publisher", publisher.getName());
    } 

    @Test
    public void testDescription() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setDescription("My description");
        Assert.assertEquals("My description", publisher.getDescription());
    } 

    @Test
    public void testPublisherClass() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setPublisherClass("org.acme.publisher");
        Assert.assertEquals("org.acme.publisher", publisher.getPublisherClass());
    } 

    @Test
    public void testTemplate() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setTemplate("{ \"config\": \"configured\" }");
        Assert.assertEquals("{ \"config\": \"configured\" }", publisher.getTemplate());
    } 

    @Test
    public void testTemplateMimeType() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setTemplateMimeType("application/json");
        Assert.assertEquals("application/json", publisher.getTemplateMimeType());
    } 

    @Test
    public void testDefaultPublisher() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setDefaultPublisher(true);
        Assert.assertTrue(publisher.isDefaultPublisher());
    } 

    @Test
    public void testUuid() {
        UUID uuid = UUID.randomUUID();
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setUuid(uuid);
        Assert.assertEquals(uuid.toString(), publisher.getUuid().toString());
    } 
}
