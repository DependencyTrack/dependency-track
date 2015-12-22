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

import javax.persistence.*;
import java.util.Set;

@Entity
@Table(name ="application")
public final class Application implements Cloneable {

    /**
     * The unique identifier of the persisted object.
     */
    @Id
    @Column(name ="id")
    @GeneratedValue
    private Integer id;

    /**
     * The name of the application.
     */
    @Column(name ="name")
    @OrderBy
    private String name;

    /**
     * The version of the applications.
     */
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "application")
    @OrderBy("version")
    private Set<ApplicationVersion> versions;

    /**
     * Clones this specific object (minus the objects id).
     * @return a New object
     */
    public Object clone() {
        final Application obj = new Application();
        obj.setName(this.name);
        return obj;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Set<ApplicationVersion> getVersions() {
        return this.versions;
    }

}
