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

import com.fasterxml.jackson.annotation.JsonIgnore;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.security.Principal;

@PersistenceCapable
public class ApiKey implements Serializable, Principal {

    private static final long serialVersionUID = -6188881997158839315L;

    @PrimaryKey
    @Persistent(valueStrategy=IdGeneratorStrategy.INCREMENT)
    @JsonIgnore
    private long id;

    @Persistent
    @Unique(name="APIKEY_IDX")
    @Column(name="APIKEY", jdbcType="VARCHAR", length=32, allowsNull="false")
    private String key;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    /**
     * Do not use - only here to satisfy Principal implementation requirement
     * @deprecated use {@link LdapUser#getUsername()}
     */
    @Deprecated
    @JsonIgnore
    public String getName() {
        return getKey();
    }

}
