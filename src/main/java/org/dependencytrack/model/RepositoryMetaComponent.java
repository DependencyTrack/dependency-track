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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;

/**
 * Tracks third-party metadata about component groups from external repositories
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@PersistenceCapable(table = "REPOSITORY_META_COMPONENT")
@Index(name = "REPOSITORY_META_COMPONENT_COMPOUND_IDX", members = {"repositoryType", "namespace", "name"}, unique = "true")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RepositoryMetaComponent implements Serializable {

    private static final long serialVersionUID = 4415041595179460918L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    /**
     * This is an indirect representation of a the Package URL "type" field.
     */
    @Persistent(defaultFetchGroup = "true")
    @Column(name = "REPOSITORY_TYPE", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    private RepositoryType repositoryType;

    /**
     * This is a representation of the Package URL "namespace" field.
     */
    @Persistent
    @Column(name = "NAMESPACE")
    private String namespace;

    /**
     * This is a representation of the Package URL "name" field.
     */
    @Persistent
    @Column(name = "NAME", allowsNull = "false")
    @NotNull
    private String name;

    /**
     * The latest version of the component.
     */
    @Persistent
    @Column(name = "LATEST_VERSION", allowsNull = "false")
    @NotNull
    private String latestVersion;

    /**
     * The optional date when the component was last published.
     */
    @Persistent
    @Column(name = "PUBLISHED")
    private Date published;

    /**
     * The date in which the last version check of the component was made.
     */
    @Persistent
    @Column(name = "LAST_CHECK", allowsNull = "false")
    @Index(name = "REPOSITORY_META_COMPONENT_LASTCHECK_IDX")
    @NotNull
    private Date lastCheck;


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public RepositoryType getRepositoryType() {
        return repositoryType;
    }

    public void setRepositoryType(RepositoryType repositoryType) {
        this.repositoryType = repositoryType;
    }

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLatestVersion() {
        return latestVersion;
    }

    public void setLatestVersion(String latestVersion) {
        this.latestVersion = latestVersion;
    }

    public Date getPublished() {
        return published;
    }

    public void setPublished(Date published) {
        this.published = published;
    }

    public Date getLastCheck() {
        return lastCheck;
    }

    public void setLastCheck(Date lastCheck) {
        this.lastCheck = lastCheck;
    }
}
