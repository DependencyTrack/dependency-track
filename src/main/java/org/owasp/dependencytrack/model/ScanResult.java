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
import java.util.Date;

@Entity
@Table(name = "scanresult")
public class ScanResult {

    /**
     * The unique identifier of the persisted object.
     */
    @Id
    @Column(name = "id", unique = true)
    @GeneratedValue
    private Integer id;

    /**
     * The date of the scan
     */
    @Temporal(TemporalType.DATE)
    @Column(name = "scandate")
    private Date scanDate;

    /**
     * The parent application version.
     */
    @ManyToOne
    @JoinColumn(name = "libraryversionid", nullable = false)
    private LibraryVersion libraryVersion;

    /**
     * The vulnerability recorded in this scan.
     */
    @ManyToOne
    @JoinColumn(name = "vulnerabilityid", nullable = false)
    private Vulnerability vulnerability;

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

    public LibraryVersion getLibraryVersion() {
        return libraryVersion;
    }

    public void setLibraryVersion(LibraryVersion libraryVersion) {
        this.libraryVersion = libraryVersion;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }
}
