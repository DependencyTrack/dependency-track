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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.List;

@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProjectVersion implements Serializable {

    private static final long serialVersionUID = 6559534934400263812L;

    @PrimaryKey
    @Persistent(valueStrategy= IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup="true")
    @Column(name="PROJECT_ID", allowsNull="false")
    private Project project;

    @Persistent
    @Column(name="VERSION", jdbcType="VARCHAR", length=128, allowsNull="false")
    private String version;

    @Persistent(mappedBy="projectVersion")
    private List<ProjectVersionProperty> properties;

    @Persistent
    @Unique(name="PROJECTVERSION_UUID_IDX")
    @Column(name="UUID", jdbcType="VARCHAR", length=36, allowsNull="false")
    private String uuid;

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

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public List<ProjectVersionProperty> getProperties() {
        return properties;
    }

    public void setProperties(List<ProjectVersionProperty> properties) {
        this.properties = properties;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }
}
