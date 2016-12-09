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
import com.fasterxml.jackson.annotation.JsonInclude;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;

@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Evidence implements Serializable {

    private static final long serialVersionUID = 6801194446909782113L;

    @PrimaryKey
    @Persistent(valueStrategy= IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup="true")
    @Column(name="COMPONENT_ID", allowsNull="false")
    private Component component;

    @Persistent
    @Column(name="TYPE", jdbcType="VARCHAR", length=128)
    private String type;

    @Persistent
    @Column(name="CONFIDENCE")
    private int confidence;

    @Persistent
    @Column(name="SOURCE", jdbcType="VARCHAR", length=128, allowsNull="false")
    private String source;

    @Persistent
    @Column(name="NAME", jdbcType="VARCHAR", length=128, allowsNull="false")
    private String name;

    @Persistent
    @Column(name="VALUE", jdbcType="VARCHAR", length=4096)
    private String value;

    @Persistent
    @Unique(name="EVIDENCE_UUID_IDX")
    @Column(name="UUID", jdbcType="VARCHAR", length=36, allowsNull="false")
    private String uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public int getConfidence() {
        return confidence;
    }

    public void setConfidence(int confidence) {
        this.confidence = confidence;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Component getComponent() {
        return component;
    }

    public void setComponent(Component component) {
        this.component = component;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }
}
