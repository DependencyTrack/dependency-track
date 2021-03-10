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

import alpine.json.TrimmedStringArrayDeserializer;
import alpine.json.TrimmedStringDeserializer;
import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.FetchGroup;
import javax.jdo.annotations.FetchGroups;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Serialized;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Model class for tracking service components.
 *
 * @author Steve Springett
 * @since 4.2.0
 */
@PersistenceCapable
@FetchGroups({
        @FetchGroup(name = "ALL", members = {
                @Persistent(name = "provider"),
                @Persistent(name = "project"),
                @Persistent(name = "externalReferences"),
                @Persistent(name = "parent"),
                @Persistent(name = "children"),
                @Persistent(name = "vulnerabilities"),
        })
})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ServiceComponent implements Serializable {

    private static final long serialVersionUID = -2892070816561705642L;

    /**
     * Defines JDO fetch groups for this class.
     */
    public enum FetchGroup {
        ALL
    }

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PROVIDER_ID")
    @Serialized
    private OrganizationalEntity provider;

    @Persistent
    @Column(name = "GROUP", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The group may only contain printable characters")
    private String group;

    @Persistent
    @Column(name = "NAME", jdbcType = "VARCHAR", allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    private String name;

    @Persistent
    @Column(name = "VERSION", jdbcType = "VARCHAR")
    @Size(max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The version may only contain printable characters")
    private String version;

    @Persistent
    @Column(name = "DESCRIPTION", jdbcType = "VARCHAR", length = 1024)
    @Size(max = 1024)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The description may only contain printable characters")
    private String description;

    @Persistent(defaultFetchGroup = "true")
    @Serialized
    @Column(name = "ENDPOINTS", jdbcType = "LONGVARBINARY")
    @JsonDeserialize(using = TrimmedStringArrayDeserializer.class)
    private String[] endpoints;

    @Persistent
    @Column(name = "AUTHENTICATED")
    private Boolean authenticated;

    @Persistent
    @Column(name = "X_TRUST_BOUNDARY")
    private Boolean crossesTrustBoundary;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "DATA")
    @Serialized
    private List<DataClassification> data;

    //TODO add license support once Component license support is refactored

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "EXTERNAL_REFERENCES")
    @Serialized
    private List<ExternalReference> externalReferences;

    @Persistent
    @Column(name = "PARENT_SERVICECOMPONENT_ID")
    private ServiceComponent parent;

    @Persistent(mappedBy = "parent")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private Collection<ServiceComponent> children;

    @Persistent(table = "SERVICECOMPONENTS_VULNERABILITIES")
    @Join(column = "SERVICECOMPONENT_ID")
    @Element(column = "VULNERABILITY_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private List<Vulnerability> vulnerabilities;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @NotNull
    private Project project;

    /**
     * Convenience field which stores the Inherited Risk Score (IRS) of the last metric in the {@link DependencyMetrics} table
     */
    @Persistent
    @Index(name = "SERVICECOMPONENT_LAST_RISKSCORE_IDX")
    @Column(name = "LAST_RISKSCORE", allowsNull = "false", defaultValue = "0")
    private Double lastInheritedRiskScore;

    /**
     * Sticky notes
     */
    @Persistent(defaultFetchGroup = "true")
    @Column(name = "TEXT", jdbcType = "CLOB")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String notes;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "SERVICECOMPONENT_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    private transient String bomRef;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public OrganizationalEntity getProvider() {
        return provider;
    }

    public void setProvider(OrganizationalEntity provider) {
        this.provider = provider;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(String group) {
        this.group = group;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String[] getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(String[] endpoints) {
        this.endpoints = endpoints;
    }

    public Boolean getAuthenticated() {
        return authenticated;
    }

    public void setAuthenticated(Boolean authenticated) {
        this.authenticated = authenticated;
    }

    public Boolean getCrossesTrustBoundary() {
        return crossesTrustBoundary;
    }

    public void setCrossesTrustBoundary(Boolean crossesTrustBoundary) {
        this.crossesTrustBoundary = crossesTrustBoundary;
    }

    public List<DataClassification> getData() {
        return data;
    }

    public void addData(DataClassification data) {
        if (this.data == null) {
            this.data = new ArrayList<>();
        }
        this.data.add(data);
    }

    public void setData(List<DataClassification> data) {
        this.data = data;
    }

    public List<ExternalReference> getExternalReferences() {
        return externalReferences;
    }

    public void addExternalReference(ExternalReference externalReferences) {
        if (this.externalReferences == null) {
            this.externalReferences = new ArrayList<>();
        }
        this.externalReferences.add(externalReferences);
    }

    public void setExternalReferences(List<ExternalReference> externalReferences) {
        this.externalReferences = externalReferences;
    }

    public ServiceComponent getParent() {
        return parent;
    }

    public void setParent(ServiceComponent parent) {
        this.parent = parent;
    }

    public Collection<ServiceComponent> getChildren() {
        return children;
    }

    public void setChildren(Collection<ServiceComponent> children) {
        this.children = children;
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public Double getLastInheritedRiskScore() {
        return lastInheritedRiskScore;
    }

    public void setLastInheritedRiskScore(Double lastInheritedRiskScore) {
        this.lastInheritedRiskScore = lastInheritedRiskScore;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public String getBomRef() {
        return bomRef;
    }

    public void setBomRef(String bomRef) {
        this.bomRef = bomRef;
    }
}
