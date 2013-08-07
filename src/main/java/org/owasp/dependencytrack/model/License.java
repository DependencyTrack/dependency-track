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
import java.sql.Blob;
import java.sql.Clob;
import java.util.Set;

@Entity
@Table(name = "LICENSES")
public class License implements Cloneable {

    @Id
    @Column(name = "ID")
    @GeneratedValue
    private Integer id;

    @Column(name = "LICENSENAME")
    @OrderBy
    private String licensename;

    @Column(name = "TEXT")
    @Lob
    private Blob text;

    @Column(name = "URL")
    @Lob
    private Clob url;

    @Column(name = "FILENAME")
    private String filename;

    @Column(name = "CONTENTTYPE")
    private String contenttype;

    @OneToMany(fetch = FetchType.EAGER, mappedBy = "license")
    private Set<Library> libraries;


    public Object clone() {
        License obj = new License();
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