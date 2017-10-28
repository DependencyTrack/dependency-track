/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.model;

import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.UUID;

/**
 * Model for tracking various metadata uses as evidence in identifying components.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Evidence implements Serializable {

    private static final long serialVersionUID = 6801194446909782113L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "COMPONENT_ID", allowsNull = "false")
    private Component component;

    @Persistent
    @Column(name = "TYPE", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The type may only contain printable characters")
    private String type;

    @Persistent
    @Column(name = "CONFIDENCE")
    private int confidence;

    @Persistent
    @Column(name = "SOURCE", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The source may only contain printable characters")
    private String source;

    @Persistent
    @Column(name = "NAME", jdbcType = "VARCHAR", length = 128, allowsNull = "false")
    @NotNull
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    private String name;

    @Persistent
    @Column(name = "VALUE", jdbcType = "VARCHAR", length = 4096)
    @Size(max = 4096)
    // NOTE: Evidence may contain control characters and unicode replacement characters.
    // Nearly impossible to perform positive input validation on this field.
    private String value;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "EVIDENCE_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public int getConfidence() {
        return confidence;
    }

    public void setConfidence(int confidence) {
        this.confidence = confidence;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Component getComponent() {
        return component;
    }

    public void setComponent(Component component) {
        this.component = component;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
