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
import java.io.Serializable;
import java.util.UUID;

/**
 * Tracks third-party metadata about component groups from external repositories
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@PersistenceCapable(table = "REPOSITORY")
@Unique(name = "REPOSITORY_COMPOUND_IDX", members = {"type", "identifier"})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Repository implements Serializable {

    private static final long serialVersionUID = -3875882921059813747L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "TYPE", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    private RepositoryType type;

    @Persistent
    @Column(name = "IDENTIFIER", allowsNull = "false")
    @NotBlank
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String identifier;

    @Persistent
    @Column(name = "URL")
    @NotBlank
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String url;

    @Persistent
    @Column(name = "RESOLUTION_ORDER")
    @NotNull
    private int resolutionOrder;

    @Persistent
    @Column(name = "ENABLED")
    @NotNull
    private boolean enabled;

    @Persistent
    @Column(name = "INTERNAL")
    @NotNull
    private Boolean internal; // New column, must allow nulls on existing databases

    @Persistent(customValueStrategy = "uuid")
    @Index(name = "REPOSITORY_UUID_IDX") // Cannot be @Unique. Microsoft SQL Server throws an exception
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "true")  // New column, must allow nulls on existing databases
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public RepositoryType getType() {
        return type;
    }

    public void setType(RepositoryType type) {
        this.type = type;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getResolutionOrder() {
        return resolutionOrder;
    }

    public void setResolutionOrder(int resolutionOrder) {
        this.resolutionOrder = resolutionOrder;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Boolean isInternal() {
        return internal;
    }

    public void setInternal(Boolean internal) {
        this.internal = internal;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
