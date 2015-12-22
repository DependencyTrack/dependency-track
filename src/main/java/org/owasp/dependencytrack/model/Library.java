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
@Table(name = "library")
public final class Library implements Cloneable {

    /**
     * The unique identifier of the persisted object.
     */
    @Id
    @Column(name = "id")
    @GeneratedValue
    private Integer id;

    /**
     * The name of the library (i.e. Commons-Lang).
     */
    @Column(name = "libraryname")
    @OrderBy
    private String libraryname;

    /**
     * The license the library is licensed under.
     */
    @ManyToOne
    @JoinColumn(name = "licenseid")
    @OrderBy
    private License license;

    /**
     * The vendor of the library (i.e. Apache).
     */
    @ManyToOne
    @JoinColumn(name = "libraryvendorid")
    @OrderBy
    private LibraryVendor libraryVendor;

    /**
     * The programming language the library was written in (i.e. Java).
     */
    @Column(name = "lang")
    private String language;

    /**
     * A Set of all versions of this library
     */
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "library")
    private Set<LibraryVersion> versions;

    /**
     * Clones this specific object (minus the objects id).
     * @return a New object
     */
    public Object clone() {
        final Library obj = new Library();
        obj.setLanguage(this.language);
        obj.setLibraryname(this.libraryname);
        obj.setLibraryVendor(this.libraryVendor);
        obj.setLicense(this.license);

        return obj;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getLibraryname() {
        return libraryname;
    }

    public void setLibraryname(String libraryname) {
        this.libraryname = libraryname;
    }

    public License getLicense() {
        return license;
    }

    public void setLicense(License license) {
        this.license = license;
    }


    public LibraryVendor getLibraryVendor() {
        return libraryVendor;
    }

    public void setLibraryVendor(LibraryVendor libraryVendor) {
        this.libraryVendor = libraryVendor;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public Set<LibraryVersion> getVersions() {
        return versions;
    }

    public void setVersions(Set<LibraryVersion> versions) {
        this.versions = versions;
    }
}
