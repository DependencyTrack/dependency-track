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

import java.util.UUID;

class NotificationPublisherTest {

    @Test
    void testId() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setId(111L);
        Assertions.assertEquals(111L, publisher.getId());
    } 

    @Test
    void testName() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setName("My Publisher");
        Assertions.assertEquals("My Publisher", publisher.getName());
    } 

    @Test
    void testDescription() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setDescription("My description");
        Assertions.assertEquals("My description", publisher.getDescription());
    } 

    @Test
    void testPublisherClass() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setPublisherClass("org.acme.publisher");
        Assertions.assertEquals("org.acme.publisher", publisher.getPublisherClass());
    } 

    @Test
    void testTemplate() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setTemplate("{ \"config\": \"configured\" }");
        Assertions.assertEquals("{ \"config\": \"configured\" }", publisher.getTemplate());
    } 

    @Test
    void testTemplateMimeType() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setTemplateMimeType("application/json");
        Assertions.assertEquals("application/json", publisher.getTemplateMimeType());
    } 

    @Test
    void testDefaultPublisher() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setDefaultPublisher(true);
        Assertions.assertTrue(publisher.isDefaultPublisher());
    } 

    @Test
    void testUuid() {
        UUID uuid = UUID.randomUUID();
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setUuid(uuid);
        Assertions.assertEquals(uuid.toString(), publisher.getUuid().toString());
    } 
}
