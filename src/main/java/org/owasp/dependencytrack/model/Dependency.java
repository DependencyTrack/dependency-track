/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.model;

import alpine.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.FetchGroup;
import javax.jdo.annotations.FetchGroups;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;

/**
 * Model for tracking what {@link Component}s are used in what {@link Project}s.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable
@FetchGroups({
        @FetchGroup(name = "ALL", members = {
                @Persistent(name = "project"),
                @Persistent(name = "component"),
                @Persistent(name = "addedBy"),
                @Persistent(name = "addedOn"),
                @Persistent(name = "notes")
        }),
        @FetchGroup(name = "PROJECT_ONLY", members = {
                @Persistent(name = "project"),
                @Persistent(name = "addedBy"),
                @Persistent(name = "addedOn"),
                @Persistent(name = "notes")
        }),
        @FetchGroup(name = "COMPONENT_ONLY", members = {
                @Persistent(name = "component"),
                @Persistent(name = "addedBy"),
                @Persistent(name = "addedOn"),
                @Persistent(name = "notes")
        })
})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Dependency implements Serializable {

    /**
     * Defines names of JDO fetch groups for this class.
     */
    public enum FetchGroup {
        ALL,
        PROJECT_ONLY,
        COMPONENT_ONLY
    }

    private static final long serialVersionUID = 5403576959561421178L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "false")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @NotNull
    private Project project;

    @Persistent(defaultFetchGroup = "false")
    @Column(name = "COMPONENT_ID", allowsNull = "false")
    @NotNull
    private Component component;

    @Persistent
    @Column(name = "ADDED_BY")
    private String addedBy;

    @Persistent
    @Column(name = "ADDED_ON", jdbcType = "TIMESTAMP", allowsNull = "false")
    @NotNull
    private Date addedOn;

    @Persistent
    @Column(name = "NOTES", jdbcType = "CLOB")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String notes;

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

    public Component getComponent() {
        return component;
    }

    public void setComponent(Component component) {
        this.component = component;
    }

    public String getAddedBy() {
        return addedBy;
    }

    public void setAddedBy(String addedBy) {
        this.addedBy = addedBy;
    }

    public Date getAddedOn() {
        return addedOn;
    }

    public void setAddedOn(Date addedOn) {
        this.addedOn = addedOn;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

}
