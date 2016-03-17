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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OrderBy;
import javax.persistence.Table;
import java.util.UUID;

@Entity
@Table(name = "libraryversion")
public final class LibraryVersion implements Cloneable {

    /**
     * The unique identifier of the persisted object.
     */
    @Id
    @Column(name = "id")
    @GeneratedValue
    private Integer id;

    /**
     * The String representation of the version of the library (i.e. 1.3.0).
     */
    @Column(name = "libraryversion")
    @OrderBy
    private String libraryversion;

    /**
     * The parent Library object for this version.
     */
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "libraryid", nullable = false)
    private Library library;

    /**
     * The String representation of the SHA-1 hash
     */
    @Column(name = "SHA1")
    private String sha1;

    /**
     * The String representation of the MD5 hash
     */
    @Column(name = "MD5")
    private String md5;

    /**
     * The String representation of a universally unique identifier
     */
    @Column(name = "uuid")
    private String uuid;

    /**
     * The number of vulnerabilities associated with this ApplicationVersion.
     * This status is updated periodically by the system and is primarily used
     * used to reduce unnecessary SQL queries to calculate this statistic.
     */
    @Column(name = "vulncount")
    private Integer vulnCount = 0;

    /**
     * Clones this specific object (minus the objects id).
     * @return a New object
     */
    public Object clone() {
        final LibraryVersion obj = new LibraryVersion();
        obj.setLibrary(this.library);
        obj.setLibraryversion(this.libraryversion);
        obj.setMd5(this.md5);
        obj.setSha1(this.sha1);
        obj.setUuid(UUID.randomUUID().toString());
        obj.setVulnCount(0);
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

    public String getSha1() {
        return sha1;
    }

    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getUuidAsMd5Hash() {
        return uuid.replace("-", "");
    }

    public String getUuidAsSha1Hash() {
        return "00000000".concat(uuid.replace("-", ""));
    }

    public Integer getVulnCount() {
        return vulnCount;
    }

    public void setVulnCount(Integer vulnCount) {
        this.vulnCount = vulnCount;
    }
}
