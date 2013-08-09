/*
 * Copyright 2013 Axway
 *
 * This file is part of OWASP Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with Dependency-Track.
 * If not, see http://www.gnu.org/licenses/.
 */

package org.owasp.dependencytrack.model;

import javax.persistence.*;

@Entity
@Table(name = "LIBRARYVERSION")
public final class LibraryVersion implements Cloneable {

    @Id
    @Column(name = "ID")
    @GeneratedValue
    private Integer id;

    @Column(name = "LIBRARYVERSION")
    @OrderBy
    private String libraryversion;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "LIBRARYID", nullable = false)
    private Library library;

    @Column(name = "SECUNIA", nullable = true)
    private Integer secunia;

    public Object clone() {
        LibraryVersion obj = new LibraryVersion();
        obj.setLibrary(this.library);
        obj.setLibraryversion(this.libraryversion);
        obj.setSecunia(this.secunia);
        return obj;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getLibraryversion() {
        return libraryversion;
    }

    public void setLibraryversion(String libraryversion) {
        this.libraryversion = libraryversion;
    }

    public Library getLibrary() {
        return library;
    }

    public void setLibrary(Library library) {
        this.library = library;
    }

    public Integer getSecunia() {
        return secunia;
    }

    public void setSecunia(Integer secunia) {
        this.secunia = secunia;
    }

}