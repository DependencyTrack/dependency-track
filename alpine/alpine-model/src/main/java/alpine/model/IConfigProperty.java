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

/**
 * Interface definition for configuration properties.
 *
 * @author Steve Springett
 * @since 1.4.3
 */
public interface IConfigProperty {

    public enum PropertyType {
        BOOLEAN,
        INTEGER,
        NUMBER,
        STRING,
        TIMESTAMP,
        URL,
        UUID
    }

    long getId();

    void setId(long id);

    String getGroupName();

    void setGroupName(String groupName);

    String getPropertyName();

    void setPropertyName(String propertyName);

    String getPropertyValue();

    void setPropertyValue(String propertyValue);

    ConfigProperty.PropertyType getPropertyType();

    void setPropertyType(ConfigProperty.PropertyType propertyType);

    String getDescription();

    void setDescription(String description);

}
