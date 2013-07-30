/*
 * Copyright 2013 OWASP Foundation
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
import java.util.Set;

@Entity
@Table(name = "APPLICATIONVERSION")
public class ApplicationVersion implements Cloneable {

    @Id
    @Column(name = "ID")
    @GeneratedValue
    private Integer id;

    @Column(name = "VERSION", nullable=false)
    private String version;

    @ManyToOne
    @JoinColumn(name = "APPID", nullable=false)
    private Application application;


    public Object clone() {
        ApplicationVersion obj = new ApplicationVersion();
        obj.setApplication(this.application);
        obj.setVersion(this.version);
        return obj;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public Application getApplication() {
        return application;
    }

    public void setApplication(Application application) {
        this.application = application;
    }


}