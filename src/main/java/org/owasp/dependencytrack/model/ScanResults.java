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
 *
 * Copyright (c) Axway. All Rights Reserved.
 */

package org.owasp.dependencytrack.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import java.util.Date;
import java.util.Set;

@Entity
@Table(name = "SCANRESULTS")
public class ScanResults {

    /**
     * The unique identifier of the persisted object.
     */
    @Id
    @Column(name = "ID", unique = true)
    @GeneratedValue
    private Integer id;

    /**
     * The date of the scan
     */
    @Temporal(TemporalType.DATE)
    @Column(name = "SCANDATE")
    private Date scanDate;

    /**
     * The UUID characters
     */
    @Column(name = "UUID")
    private String UUID;

    /**
     * The vulnerabilities mapped to a scan
     */
    @OneToMany(mappedBy = "scanResults", fetch = FetchType.EAGER)
    private Set<Vulnerability> vulnerabilities;

    /**
     * The parent application version.
     */
    @ManyToOne
    @JoinColumn(name = "LIBRARYVERSIONID", nullable = false)
    private LibraryVersion libraryVersion;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Date getScanDate() {
        return scanDate;
    }

    public void setScanDate(Date scanDate) {
        this.scanDate = scanDate;
    }

    public String getUUID() {
        return UUID;
    }

    public void setUUID(String UUID) {
        this.UUID = UUID;
    }

    public LibraryVersion getLibraryVersion() {
        return libraryVersion;
    }

    public void setLibraryVersion(LibraryVersion libraryVersion) {
        this.libraryVersion = libraryVersion;
    }

}
