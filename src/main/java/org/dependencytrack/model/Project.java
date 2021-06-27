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
import alpine.model.Team;
import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.resources.v1.serializers.CustomPackageURLSerializer;
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
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Model for tracking individual projects. Projects are high-level containers
 * of components and (optionally) other projects. Project are often software
 * applications, firmware, operating systems, or devices.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable
@FetchGroups({
        @FetchGroup(name = "ALL", members = {
                @Persistent(name = "name"),
                @Persistent(name = "author"),
                @Persistent(name = "publisher"),
                @Persistent(name = "group"),
                @Persistent(name = "name"),
                @Persistent(name = "description"),
                @Persistent(name = "version"),
                @Persistent(name = "classifier"),
                @Persistent(name = "cpe"),
                @Persistent(name = "purl"),
                @Persistent(name = "swidTagId"),
                @Persistent(name = "uuid"),
                @Persistent(name = "parent"),
                @Persistent(name = "children"),
                @Persistent(name = "properties"),
                @Persistent(name = "tags"),
                @Persistent(name = "accessTeams")
        })
})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Project implements Serializable {

    private static final long serialVersionUID = -7592438796591673355L;

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

    @Persistent
    @Column(name = "AUTHOR", jdbcType = "VARCHAR")
    @Size(max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The author may only contain printable characters")
    private String author;

    @Persistent
    @Column(name = "PUBLISHER", jdbcType = "VARCHAR")
    @Size(max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The publisher may only contain printable characters")
    private String publisher;

    @Persistent
    @Column(name = "GROUP", jdbcType = "VARCHAR")
    @Index(name = "PROJECT_GROUP_IDX")
    @Size(max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The group may only contain printable characters")
    private String group;

    @Persistent
    @Index(name = "PROJECT_NAME_IDX")
    @Column(name = "NAME", jdbcType = "VARCHAR", allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    private String name;

    @Persistent
    @Column(name = "DESCRIPTION", jdbcType = "VARCHAR")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The description may only contain printable characters")
    private String description;

    @Persistent
    @Index(name = "PROJECT_VERSION_IDX")
    @Column(name = "VERSION", jdbcType = "VARCHAR")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The version may only contain printable characters")
    private String version;

    @Persistent
    @Column(name = "CLASSIFIER", jdbcType = "VARCHAR")
    @Index(name = "PROJECT_CLASSIFIER_IDX")
    @Extension(vendorName = "datanucleus", key = "enum-check-constraint", value = "true")
    private Classifier classifier;

    @Persistent
    @Index(name = "PROJECT_CPE_IDX")
    @Size(max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    //Patterns obtained from https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd
    @Pattern(regexp = "(cpe:2\\.3:[aho\\*\\-](:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|}~]))+(\\?*|\\*?))|[\\*\\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\\*\\-]))(:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|}~]))+(\\?*|\\*?))|[\\*\\-])){4})|([c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9\\._\\-~%]*){0,6})", message = "The CPE must conform to the CPE v2.2 or v2.3 specification defined by NIST")
    private String cpe;

    @Persistent
    @Index(name = "PROJECT_PURL_IDX")
    @Size(max = 255)
    @com.github.packageurl.validator.PackageURL
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String purl;

    @Persistent
    @Index(name = "PROJECT_SWID_TAGID_IDX")
    @Size(max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The SWID tagId may only contain printable characters")
    private String swidTagId;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "DIRECT_DEPENDENCIES", jdbcType = "CLOB")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String directDependencies; // This will be a JSON string

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "PROJECT_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    @Persistent
    @Column(name = "PARENT_PROJECT_ID")
    private Project parent;

    @Persistent(mappedBy = "parent")
    private Collection<Project> children;

    @Persistent(mappedBy = "project", defaultFetchGroup = "true")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "groupName ASC, propertyName ASC"))
    private List<ProjectProperty> properties;

    @Persistent(table = "PROJECTS_TAGS", defaultFetchGroup = "true", mappedBy = "projects")
    @Join(column = "PROJECT_ID")
    @Element(column = "TAG_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "name ASC"))
    private List<Tag> tags;

    /**
     * Convenience field which will contain the date of the last entry in the {@link Bom} table
     */
    @Persistent
    @Index(name = "PROJECT_LASTBOMIMPORT_IDX")
    @Column(name = "LAST_BOM_IMPORTED")
    private Date lastBomImport;

    /**
     * Convenience field which will contain the format of the last entry in the {@link Bom} table
     */
    @Persistent
    @Index(name = "PROJECT_LASTBOMIMPORT_FORMAT_IDX")
    @Column(name = "LAST_BOM_IMPORTED_FORMAT")
    private String lastBomImportFormat;

    /**
     * Convenience field which stores the Inherited Risk Score (IRS) of the last metric in the {@link ProjectMetrics} table
     */
    @Persistent
    @Index(name = "PROJECT_LAST_RISKSCORE_IDX")
    @Column(name = "LAST_RISKSCORE", allowsNull = "true") // New column, must allow nulls on existing databases))
    private Double lastInheritedRiskScore;

    @Persistent
    @Column(name = "ACTIVE")
    private Boolean active; // Added in v3.6. Existing records need to be nullable on upgrade.

    @Persistent(table = "PROJECT_ACCESS_TEAMS", defaultFetchGroup = "true")
    @Join(column = "PROJECT_ID")
    @Element(column = "TEAM_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "name ASC"))
    @JsonIgnore
    private List<Team> accessTeams;

    private transient ProjectMetrics metrics;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public String getPublisher() {
        return publisher;
    }

    public void setPublisher(String publisher) {
        this.publisher = publisher;
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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public Classifier getClassifier() {
        return classifier;
    }

    public void setClassifier(Classifier classifier) {
        this.classifier = classifier;
    }

    public String getCpe() {
        return cpe;
    }

    public void setCpe(String cpe) {
        this.cpe = cpe;
    }

    @JsonSerialize(using = CustomPackageURLSerializer.class)
    public PackageURL getPurl() {
        try {
            return new PackageURL(purl);
        } catch (MalformedPackageURLException e) {
            return null;
        }
    }

    public void setPurl(PackageURL purl) {
        if (purl != null) {
            this.purl = purl.canonicalize();
        } else {
            this.purl = null;
        }
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }

    public String getSwidTagId() {
        return swidTagId;
    }

    public void setSwidTagId(String swidTagId) {
        this.swidTagId = swidTagId;
    }

    public String getDirectDependencies() {
        return directDependencies;
    }

    public void setDirectDependencies(String directDependencies) {
        this.directDependencies = directDependencies;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public Project getParent() {
        return parent;
    }

    public void setParent(Project parent) {
        this.parent = parent;
    }

    public Collection<Project> getChildren() {
        return children;
    }

    public void setChildren(Collection<Project> children) {
        this.children = children;
    }

    public List<ProjectProperty> getProperties() {
        return properties;
    }

    public void setProperties(List<ProjectProperty> properties) {
        this.properties = properties;
    }

    public List<Tag> getTags() {
        return tags;
    }

    public void setTags(List<Tag> tags) {
        this.tags = tags;
    }

    public Date getLastBomImport() {
        return lastBomImport;
    }

    public void setLastBomImport(Date lastBomImport) {
        this.lastBomImport = lastBomImport;
    }

    public String getLastBomImportFormat() {
        return lastBomImportFormat;
    }

    public void setLastBomImportFormat(String lastBomImportFormat) {
        this.lastBomImportFormat = lastBomImportFormat;
    }

    public Double getLastInheritedRiskScore() {
        return lastInheritedRiskScore;
    }

    public void setLastInheritedRiskScore(Double lastInheritedRiskScore) {
        this.lastInheritedRiskScore = lastInheritedRiskScore;
    }

    public boolean isActive() {
        if (active == null) {
            return true;
        }
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public ProjectMetrics getMetrics() {
        return metrics;
    }

    public void setMetrics(ProjectMetrics metrics) {
        this.metrics = metrics;
    }

    public List<Team> getAccessTeams() {
        return accessTeams;
    }

    public void setAccessTeams(List<Team> accessTeams) {
        this.accessTeams = accessTeams;
    }

    public void addAccessTeam(Team accessTeam) {
        if (this.accessTeams == null) {
            this.accessTeams = new ArrayList<>();
        }
        this.accessTeams.add(accessTeam);
    }

    @Override
    public String toString() {
        if (getPurl() != null) {
            return getPurl().canonicalize();
        } else {
            StringBuilder sb = new StringBuilder();
            if (getGroup() != null) {
                sb.append(getGroup()).append(" : ");
            }
            sb.append(getName());
            if (getVersion() != null) {
                sb.append(" : ").append(getVersion());
            }
            return sb.toString();
        }
    }
}
