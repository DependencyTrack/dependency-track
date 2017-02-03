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
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;

@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Component implements Serializable {

    private static final long serialVersionUID = 6841650046433674702L;

    @PrimaryKey
    @Persistent(valueStrategy= IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name="GROUP", jdbcType="VARCHAR")
    @Index(name="COMPONENT_GROUP_IDX")
    private String group;

    @Persistent
    @Column(name="NAME", jdbcType="VARCHAR", allowsNull="false")
    @Index(name="COMPONENT_NAME_IDX")
    private String name;

    @Persistent
    @Column(name="VERSION", jdbcType="VARCHAR")
    private String version;

    @Persistent
    @Column(name="CLASSIFIER", jdbcType="VARCHAR")
    @Index(name="COMPONENT_CLASSIFIER_IDX")
    private String classifier;

    @Persistent
    @Column(name="FILENAME", jdbcType="VARCHAR")
    private String filename;

    @Persistent
    @Column(name="EXTENSION", jdbcType="VARCHAR")
    private String extension;

    @Persistent
    @Index(name="COMPONENT_MD5_IDX")
    @Column(name="MD5", jdbcType="VARCHAR", length=32)
    private String md5;

    @Persistent
    @Index(name="COMPONENT_SHA1_IDX")
    @Column(name="SHA1", jdbcType="VARCHAR", length=40)
    private String sha1;

    @Persistent
    @Column(name="DESCRIPTION", jdbcType="VARCHAR", length=1024)
    private String description;

    @Persistent
    @Column(name="LICENSE", jdbcType="VARCHAR")
    private String license;

    @Persistent
    @Column(name="LICENSE_ID")
    private License resolvedLicense;

    @Persistent
    @Column(name="PARENT_COMPONENT_ID")
    private Component parent;

    @Persistent(mappedBy="parent")
    private Collection<Component> children;

    @Persistent(mappedBy="component")
    private Collection<Evidence> evidence;

    @Persistent
    @Order(extensions=@Extension(vendorName="datanucleus", key="list-ordering", value="id ASC"))
    List<Scan> scans;

    @Persistent
    @Unique(name="COMPONENT_UUID_IDX")
    @Column(name="UUID", jdbcType="VARCHAR", length=36, allowsNull="false")
    private String uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(String group) {
        this.group = group;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getClassifier() {
        return classifier;
    }

    public void setClassifier(String classifier) {
        this.classifier = classifier;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public String getExtension() {
        return extension;
    }

    public void setExtension(String extension) {
        this.extension = extension;
    }

    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    public String getSha1() {
        return sha1;
    }

    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getLicense() {
        return license;
    }

    public void setLicense(String license) {
        this.license = license;
    }

    public License getResolvedLicense() {
        return resolvedLicense;
    }

    public void setResolvedLicense(License resolvedLicense) {
        this.resolvedLicense = resolvedLicense;
    }

    public Component getParent() {
        return parent;
    }

    public void setParent(Component parent) {
        this.parent = parent;
    }

    public Collection<Component> getChildren() {
        return children;
    }

    public void setChildren(Collection<Component> children) {
        this.children = children;
    }

    public Collection<Evidence> getEvidence() {
        return evidence;
    }

    public void setEvidence(Collection<Evidence> evidence) {
        this.evidence = evidence;
    }

    public List<Scan> getScans() {
        return scans;
    }

    public void setScans(List<Scan> scans) {
        this.scans = scans;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }
}
