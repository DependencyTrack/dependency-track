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

@Entity
@Table(name ="applicationdependency")
public final class ApplicationDependency implements Cloneable {

    /**
     * The unique identifier of the persisted object.
     */
    @Id
    @Column(name ="id")
    @GeneratedValue
    private Integer id;

    /**
     * The version of the library an applicationVersion has a dependency on.
     */
    @OneToOne
    @JoinColumn(name ="libraryversionid")
    private LibraryVersion libraryVersion;

    /**
     * The version of the application of this dependency.
     */
    @OneToOne
    @JoinColumn(name ="appversionid")
    private ApplicationVersion applicationVersion;

    /**
     * Clones this specific object (minus the objects id).
     * @return a New object
     */
    public Object clone() {
        final ApplicationDependency obj = new ApplicationDependency();
        obj.setLibraryVersion(this.libraryVersion);
        obj.setApplicationVersion(this.applicationVersion);
        return obj;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public LibraryVersion getLibraryVersion() {
        return libraryVersion;
    }

    public void setLibraryVersion(LibraryVersion libraryVersion) {
        this.libraryVersion = libraryVersion;
    }

    public ApplicationVersion getApplicationVersion() {
        return applicationVersion;
    }

    public void setApplicationVersion(ApplicationVersion applicationVersion) {
        this.applicationVersion = applicationVersion;
    }

}
