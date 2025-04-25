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

import alpine.model.IConfigProperty;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class ProjectPropertyTest {

    @Test
    void testId() {
        ProjectProperty property = new ProjectProperty();
        property.setId(111L);
        Assertions.assertEquals(111L, property.getId());
    } 

    @Test
    void testProject() {
        Project project = new Project();
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        Assertions.assertEquals(project, property.getProject());
    }

    @Test
    void testGroupName() {
        ProjectProperty property = new ProjectProperty();
        property.setGroupName("Group Name");
        Assertions.assertEquals("Group Name", property.getGroupName());
    } 

    @Test
    void testPropertyName() {
        ProjectProperty property = new ProjectProperty();
        property.setPropertyName("Property Name");
        Assertions.assertEquals("Property Name", property.getPropertyName());
    }

    @Test
    void testPropertyValue() {
        ProjectProperty property = new ProjectProperty();
        property.setPropertyValue("Property Value");
        Assertions.assertEquals("Property Value", property.getPropertyValue());
    }

    @Test
    void testPropertyType() {
        ProjectProperty property = new ProjectProperty();
        property.setPropertyType(IConfigProperty.PropertyType.STRING);
        Assertions.assertEquals(IConfigProperty.PropertyType.STRING, property.getPropertyType());
    } 

    @Test
    void testDescription() {
        ProjectProperty property = new ProjectProperty();
        property.setDescription("Property Description");
        Assertions.assertEquals("Property Description", property.getDescription());
    }
} 
