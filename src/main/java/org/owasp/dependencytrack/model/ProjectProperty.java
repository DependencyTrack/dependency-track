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
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;

/**
 * User-defined key/value model for individual projects.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable(table = "PROJECT_PROPERTY")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProjectProperty implements Serializable {

    private static final long serialVersionUID = -821103184547741489L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "PROJECT_ID", allowsNull = "false")
    private Project project;

    @Persistent
    @Column(name = "KEY", allowsNull = "false")
    @NotNull
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The key may only contain printable characters")
    private String key;

    @Persistent
    @Column(name = "VALUE", allowsNull = "false")
    @NotNull
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The value may only contain printable characters")
    private String value;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

}
