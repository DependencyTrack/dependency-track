/*
 * This file is part of Alpine.
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
package alpine.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ConfigPropertyTest {

    @Test
    public void idTest() {
        ConfigProperty prop = new ConfigProperty();
        prop.setId(123L);
        Assertions.assertEquals(123L, prop.getId());
    }

    @Test
    public void groupNameTest() {
        ConfigProperty prop = new ConfigProperty();
        prop.setGroupName("my-group");
        Assertions.assertEquals("my-group", prop.getGroupName());
    }

    @Test
    public void propertyNameTest() {
        ConfigProperty prop = new ConfigProperty();
        prop.setPropertyName("my-property-name");
        Assertions.assertEquals("my-property-name", prop.getPropertyName());
    }

    @Test
    public void propertyValueTest() {
        ConfigProperty prop = new ConfigProperty();
        prop.setPropertyValue("my-property-value");
        Assertions.assertEquals("my-property-value", prop.getPropertyValue());
    }

    @Test
    public void propertyTypeTest() {
        ConfigProperty prop = new ConfigProperty();
        prop.setPropertyType(IConfigProperty.PropertyType.STRING);
        Assertions.assertEquals(IConfigProperty.PropertyType.STRING, prop.getPropertyType());
    }

    @Test
    public void descriptionTest() {
        ConfigProperty prop = new ConfigProperty();
        prop.setDescription("My description");
        Assertions.assertEquals("My description", prop.getDescription());
    }
}
