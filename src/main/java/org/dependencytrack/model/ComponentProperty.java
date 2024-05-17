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
import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.common.base.MoreObjects;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.validation.EnumValue;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.UUID;

/**
 * @since 4.11.0
 */
@PersistenceCapable(table = "COMPONENT_PROPERTY")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ComponentProperty implements IConfigProperty, Serializable {

    private static final long serialVersionUID = -7510889645969713080L;

    public record Identity(String group, String name, String value) {

        public Identity(final ComponentProperty property) {
            this(property.getGroupName(), property.getPropertyName(), property.getPropertyValue());
        }

    }

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "COMPONENT_ID", allowsNull = "false")
    @JsonIgnore
    private Component component;

    @Persistent
    @Column(name = "GROUPNAME")
    @Size(min = 1, max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = "\\P{Cc}+", message = "The groupName must not contain control characters")
    private String groupName;

    @Persistent
    @Column(name = "PROPERTYNAME", allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = "\\P{Cc}+", message = "The propertyName must not contain control characters")
    private String propertyName;

    @Persistent
    @Column(name = "PROPERTYVALUE", length = 1024)
    @Size(max = 1024)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = "\\P{Cc}+", message = "The propertyValue must not contain control characters")
    private String propertyValue;

    @Persistent
    @Column(name = "PROPERTYTYPE", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    // NB: Encrypted values are disallowed because it complicates identity management.
    // Because duplicate groupName/propertyName combinations are allowed, the value
    // is critical to determine property uniqueness. We'd need to decrypt encrypted
    // values prior to uniqueness checks. We'd also open the door for attackers to
    // guess the encrypted value. As of now, there is no known use-case for encrypted
    // properties on the component level.
    @EnumValue(disallowed = "ENCRYPTEDSTRING", message = "Encrypted component property values are not supported")
    private PropertyType propertyType;

    @Persistent
    @Column(name = "DESCRIPTION")
    @Size(max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = "\\P{Cc}+", message = "The description must not contain control characters")
    private String description;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "COMPONENT_PROPERTY_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(final long id) {
        this.id = id;
    }

    public Component getComponent() {
        return component;
    }

    public void setComponent(final Component component) {
        this.component = component;
    }

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(final String groupName) {
        this.groupName = groupName;
    }

    public String getPropertyName() {
        return propertyName;
    }

    public void setPropertyName(final String propertyName) {
        this.propertyName = propertyName;
    }

    public String getPropertyValue() {
        return propertyValue;
    }

    public void setPropertyValue(final String propertyValue) {
        this.propertyValue = StringUtils.abbreviate(propertyValue, 1024);
    }

    public PropertyType getPropertyType() {
        return propertyType;
    }

    public void setPropertyType(final PropertyType propertyType) {
        this.propertyType = propertyType;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(final String description) {
        this.description = description;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(final UUID uuid) {
        this.uuid = uuid;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("id", id)
                .add("component", component)
                .add("groupName", groupName)
                .add("propertyName", propertyName)
                .add("propertyValue", propertyValue)
                .add("propertyType", propertyType)
                .add("description", description)
                .add("uuid", uuid)
                .omitNullValues()
                .toString();
    }

}