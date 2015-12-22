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
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "libraryvendor")
public final class LibraryVendor implements Cloneable {

    /**
     * The unique identifier of the persisted object.
     */
    @Id
    @Column(name = "id")
    @GeneratedValue
    private Integer id;

    /**
     * The String label of the vendor (i.e. Apache)
     */
    @Column(name = "vendor")
    @OrderBy
    private String vendor;

    /**
     * A Set of libraries this vendor has created
     */
    @OneToMany(mappedBy = "libraryVendor", fetch = FetchType.EAGER)
    private Set<Library> libraries;

    /**
     * Clones this specific object (minus the objects id).
     * @return a New object
     */
    public Object clone() {
        final LibraryVendor obj = new LibraryVendor();
        obj.setVendor(this.vendor);
        return obj;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getVendor() {
        return vendor;
    }

    public void setVendor(String vendor) {
        this.vendor = vendor;
    }

    public Set<Library> getLibraries() {
        return libraries;
    }

    public void setLibraries(Set<Library> libraries) {
        this.libraries = libraries;
    }

    /**
     * Add a Library to this LibraryVendor.
     * @param library A Library object
     */
    public void addLibrary(Library library) {
        if (libraries == null) {
            libraries = new HashSet<>();
        }
        libraries.add(library);
    }

}
