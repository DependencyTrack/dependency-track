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
package org.dependencytrack.persistence.jdbi;

import alpine.model.IConfigProperty.PropertyType;
import org.dependencytrack.model.ConfigPropertyConstants;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

public final class ConfigPropertyTestUtil {

    private ConfigPropertyTestUtil() {}

    public static void createConfigPropertyWithDefaultValue(ConfigPropertyConstants property) {
        createConfigProperty(property, property.getDefaultPropertyValue());
    }

    public static void createConfigProperty(ConfigPropertyConstants property, String propertyValue) {
        createConfigProperty(
                property.getGroupName(),
                property.getPropertyName(),
                propertyValue,
                property.getPropertyType(),
                property.getDescription());
    }

    public static void createConfigProperty(
            String groupName,
            String propertyName,
            String propertyValue,
            PropertyType propertyType,
            String description) {
        useJdbiHandle(handle -> handle.createUpdate("""
            INSERT INTO "CONFIGPROPERTY" (
              "GROUPNAME"
            , "PROPERTYNAME"
            , "PROPERTYVALUE"
            , "PROPERTYTYPE"
            , "DESCRIPTION"
            )
            VALUES (
              :groupName
            , :propertyName
            , :propertyValue
            , :propertyType
            , :description
            )
            """)
                .bind("groupName", groupName)
                .bind("propertyName", propertyName)
                .bind("propertyValue", propertyValue)
                .bind("propertyType", propertyType)
                .bind("description", description)
                .execute());
    }
}
