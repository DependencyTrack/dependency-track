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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Model class for tracking Dependency-Check scans.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Scan implements Serializable {

    private static final long serialVersionUID = 3950039972008164729L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "EXECUTED", jdbcType = "TIMESTAMP", allowsNull = "false")
    @NotNull
    private Date executed;

    @Persistent
    @Column(name = "IMPORTED", jdbcType = "TIMESTAMP", allowsNull = "false")
    @NotNull
    private Date imported;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @NotNull
    private Project project;

    @Persistent(table = "SCANS_COMPONENTS", mappedBy = "scans")
    @Join(column = "SCAN_ID")
    @Element(column = "COMPONENT_ID", dependent = "true")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private List<Component> components;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "SCAN_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Date getExecuted() {
        return executed;
    }

    public void setExecuted(Date executed) {
        this.executed = executed;
    }

    public Date getImported() {
        return imported;
    }

    public void setImported(Date imported) {
        this.imported = imported;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public List<Component> getComponents() {
        return components;
    }

    public void setComponents(List<Component> components) {
        this.components = components;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
