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

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;

/**
 * Persistable object representing configuration properties.
 *
 * @author Steve Springett
 * @since 1.3.0
 */
@PersistenceCapable
@Unique(members={"groupName", "propertyName"})
public class ConfigProperty implements IConfigProperty, Serializable {

    private static final long serialVersionUID = 5286421336166302912L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    private long id;

    @Persistent
    @Column(name = "GROUPNAME", allowsNull = "false")
    private String groupName;

    @Persistent
    @Column(name = "PROPERTYNAME", allowsNull = "false")
    private String propertyName;

    @Persistent
    @Column(name = "PROPERTYVALUE", jdbcType = "CLOB")
    private String propertyValue;

    @Persistent
    @Column(name = "PROPERTYTYPE", jdbcType = "VARCHAR", allowsNull = "false")
    private PropertyType propertyType;

    @Persistent
    @Column(name = "DESCRIPTION")
    private String description;

    @Override
    public long getId() {
        return id;
    }

    @Override
    public void setId(long id) {
        this.id = id;
    }

    @Override
    public String getGroupName() {
        return groupName;
    }

    @Override
    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }

    @Override
    public String getPropertyName() {
        return propertyName;
    }

    @Override
    public void setPropertyName(String propertyName) {
        this.propertyName = propertyName;
    }

    @Override
    public String getPropertyValue() {
        return propertyValue;
    }

    @Override
    public void setPropertyValue(String propertyValue) {
        this.propertyValue = propertyValue;
    }

    @Override
    public PropertyType getPropertyType() {
        return propertyType;
    }

    @Override
    public void setPropertyType(PropertyType propertyType) {
        this.propertyType = propertyType;
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public void setDescription(String description) {
        this.description = description;
    }

}
