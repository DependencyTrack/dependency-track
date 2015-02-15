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
import javax.persistence.Lob;
import javax.persistence.OneToMany;
import javax.persistence.OrderBy;
import javax.persistence.Table;
import java.sql.Blob;
import java.sql.Clob;
import java.util.Set;

@Entity
@Table(name = "LICENSES")
public final class License implements Cloneable {

    /**
     * The unique identifier of the persisted object.
     */
    @Id
    @Column(name = "ID")
    @GeneratedValue
    private Integer id;

    /**
     * The String representation of the license name (i.e. GPL v3).
     */
    @Column(name = "LICENSENAME")
    @OrderBy
    private String licensename;

    /**
     * The contents of the license.
     */
    @Column(name = "TEXT")
    @Lob
    private Blob text;

    /**
     * The URL the license can be referenced from.
     */
    @Column(name = "URL")
    @Lob
    private Clob url;

    /**
     * The filename of the license contents that were uploaded.
     */
    @Column(name = "FILENAME")
    private String filename;

    /**
     * The content-type of the filename containing the license contents.
     */
    @Column(name = "CONTENTTYPE")
    private String contenttype;

    /**
     * Clones this specific object (minus the objects id).
     * @return a New object
     */
    public Object clone() {
        final License obj = new License();
        obj.setLicensename(this.licensename);
        obj.setText(this.text);
        obj.setUrl(this.url);
        obj.setFilename(this.filename);
        obj.setContenttype(this.contenttype);
        return obj;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getLicensename() {
        return licensename;
    }

    public void setLicensename(String licensename) {
        this.licensename = licensename;
    }

    public Blob getText() {
        return text;
    }

    public void setText(Blob text) {
        this.text = text;
    }

    public Clob getUrl() {
        return url;
    }

    public void setUrl(Clob url) {
        this.url = url;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public String getContenttype() {
        return contenttype;
    }

    public void setContenttype(String contenttype) {
        this.contenttype = contenttype;
    }

}
