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

import alpine.model.IConfigProperty;
import org.junit.Assert;
import org.junit.Test;

public class ComponentPropertyTest {

    @Test
    public void testId() {
        ComponentProperty property = new ComponentProperty();
        property.setId(111L);
        Assert.assertEquals(111L, property.getId());
    }

    @Test
    public void testProject() {
        Component component = new Component();
        ComponentProperty property = new ComponentProperty();
        property.setComponent(component);
        Assert.assertEquals(component, property.getComponent());
    }

    @Test
    public void testGroupName() {
        ComponentProperty property = new ComponentProperty();
        property.setGroupName("Group Name");
        Assert.assertEquals("Group Name", property.getGroupName());
    }

    @Test
    public void testPropertyName() {
        ComponentProperty property = new ComponentProperty();
        property.setPropertyName("Property Name");
        Assert.assertEquals("Property Name", property.getPropertyName());
    }

    @Test
    public void testPropertyValue() {
        ComponentProperty property = new ComponentProperty();
        property.setPropertyValue("Property Value");
        Assert.assertEquals("Property Value", property.getPropertyValue());
    }

    @Test
    public void testPropertyType() {
        ComponentProperty property = new ComponentProperty();
        property.setPropertyType(IConfigProperty.PropertyType.STRING);
        Assert.assertEquals(IConfigProperty.PropertyType.STRING, property.getPropertyType());
    }

    @Test
    public void testDescription() {
        ComponentProperty property = new ComponentProperty();
        property.setDescription("Property Description");
        Assert.assertEquals("Property Description", property.getDescription());
    }

} 