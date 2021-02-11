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

import alpine.json.TrimmedStringDeserializer;
import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.UUID;

/**
 * Model class for tracking external references.
 *
 * @author Steve Springett
 * @since 4.2.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ExternalReference implements Serializable {

    private static final long serialVersionUID = -5885851731192037664L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent()
    @Index(name = "EXTERNALREFERENCE_COMPONENT_ID_IDX")
    @Column(name = "COMPONENT_ID", allowsNull = "true")
    private Component component;

    @Persistent
    @Index(name = "EXTERNALREFERENCE_SERVICECOMPONENT_ID_IDX")
    @Column(name = "SERVICECOMPONENT_ID", allowsNull = "true")
    private ServiceComponent serviceComponent;

    @Persistent
    @Column(name = "TYPE", jdbcType = "VARCHAR", allowsNull = "false")
    @Size(max = 255)
    private org.cyclonedx.model.ExternalReference.Type type;

    @Persistent
    @Column(name = "URL", allowsNull = "false")
    @NotBlank
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String url;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "COMMENT", jdbcType = "CLOB")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The comment may only contain printable characters")
    private String comment;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "EXTERNALREFERENCE_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Component getComponent() {
        return component;
    }

    public void setComponent(Component component) {
        this.component = component;
    }

    public ServiceComponent getServiceComponent() {
        return serviceComponent;
    }

    public void setServiceComponent(ServiceComponent serviceComponent) {
        this.serviceComponent = serviceComponent;
    }

    public org.cyclonedx.model.ExternalReference.Type getType() {
        return type;
    }

    public void setType(org.cyclonedx.model.ExternalReference.Type type) {
        this.type = type;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
