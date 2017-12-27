/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.model;

import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.FetchGroup;
import javax.jdo.annotations.FetchGroups;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Model class for tracking individual components.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable
@FetchGroups({
        @FetchGroup(name = "ALL", members = {
                @Persistent(name = "resolvedLicense"),
                @Persistent(name = "parent"),
                @Persistent(name = "children"),
                @Persistent(name = "evidence"),
                @Persistent(name = "scans"),
                @Persistent(name = "vulnerabilities"),
        })
})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Component implements Serializable {

    private static final long serialVersionUID = 6841650046433674702L;

    /**
     * Defines JDO fetch groups for this class.
     */
    public enum FetchGroup {
        ALL
    }

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "GROUP", jdbcType = "VARCHAR")
    @Index(name = "COMPONENT_GROUP_IDX")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The group may only contain printable characters")
    private String group;

    @Persistent
    @Column(name = "NAME", jdbcType = "VARCHAR", allowsNull = "false")
    @Index(name = "COMPONENT_NAME_IDX")
    @NotNull
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    private String name;

    @Persistent
    @Column(name = "VERSION", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The version may only contain printable characters")
    private String version;

    @Persistent
    @Column(name = "CLASSIFIER", jdbcType = "VARCHAR")
    @Index(name = "COMPONENT_CLASSIFIER_IDX")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The classifier may only contain printable characters")
    private String classifier;

    @Persistent
    @Column(name = "FILENAME", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.FS_DIRECTORY_NAME, message = "The specified filename is not valid and cannot be used as a filename")
    private String filename;

    @Persistent
    @Column(name = "EXTENSION", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.FS_FILE_NAME, message = "The specified filename extension is not valid and cannot be used as a extension")
    private String extension;

    @Persistent
    @Index(name = "COMPONENT_MD5_IDX")
    @Column(name = "MD5", jdbcType = "VARCHAR", length = 32)
    @Pattern(regexp = RegexSequence.Definition.HASH_MD5, message = "The MD5 hash must be a valid 32 character HEX number")
    private String md5;

    @Persistent
    @Index(name = "COMPONENT_SHA1_IDX")
    @Column(name = "SHA1", jdbcType = "VARCHAR", length = 40)
    @Pattern(regexp = RegexSequence.Definition.HASH_SHA1, message = "The SHA1 hash must be a valid 40 character HEX number")
    private String sha1;

    @Persistent
    @Index(name = "COMPONENT_SHA256_IDX")
    @Column(name = "SHA_256", jdbcType = "VARCHAR", length = 64)
    @Pattern(regexp = RegexSequence.Definition.HASH_SHA256, message = "The SHA-256 hash must be a valid 64 character HEX number")
    private String sha256;

    @Persistent
    @Index(name = "COMPONENT_SHA512_IDX")
    @Column(name = "SHA_512", jdbcType = "VARCHAR", length = 128)
    @Pattern(regexp = RegexSequence.Definition.HASH_SHA512, message = "The SHA-512 hash must be a valid 128 character HEX number")
    private String sha512;

    @Persistent
    @Index(name = "COMPONENT_SHA3_256_IDX")
    @Column(name = "SHA3_256", jdbcType = "VARCHAR", length = 64)
    @Pattern(regexp = RegexSequence.Definition.HASH_SHA256, message = "The SHA3-256 hash must be a valid 64 character HEX number")
    private String sha3_256;

    @Persistent
    @Index(name = "COMPONENT_SHA3_512_IDX")
    @Column(name = "SHA3_512", jdbcType = "VARCHAR", length = 128)
    @Pattern(regexp = RegexSequence.Definition.HASH_SHA512, message = "The SHA3-512 hash must be a valid 128 character HEX number")
    private String sha3_512;

    @Persistent
    @Pattern(regexp = RegexSequence.Definition.HTTP_URI, message = "The Package URL (purl) must be a valid URI and conform to https://github.com/package-url/purl-spec")
    private String purl;

    @Persistent
    @Column(name = "DESCRIPTION", jdbcType = "VARCHAR", length = 1024)
    @Size(max = 1024)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The description may only contain printable characters")
    private String description;

    @Persistent
    @Column(name = "LICENSE", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The license may only contain printable characters")
    private String license;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "LICENSE_ID")
    private License resolvedLicense;

    @Persistent
    @Column(name = "PARENT_COMPONENT_ID")
    private Component parent;

    @Persistent(mappedBy = "parent")
    private Collection<Component> children;

    @Persistent(mappedBy = "component")
    private Collection<Evidence> evidence;

    @Persistent
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    @JsonIgnore
    private List<Scan> scans;

    @Persistent(table = "COMPONENTS_VULNERABILITIES")
    @Join(column = "COMPONENT_ID")
    @Element(column = "VULNERABILITY_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private List<Vulnerability> vulnerabilities;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "COMPONENT_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

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

    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    public String getSha512() {
        return sha512;
    }

    public void setSha512(String sha512) {
        this.sha512 = sha512;
    }

    public String getSha3_256() {
        return sha3_256;
    }

    public void setSha3_256(String sha3_256) {
        this.sha3_256 = sha3_256;
    }

    public String getSha3_512() {
        return sha3_512;
    }

    public void setSha3_512(String sha3_512) {
        this.sha3_512 = sha3_512;
    }

    public String getPurl() {
        return purl;
    }

    public void setPurl(String purl) {
        this.purl = purl;
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

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public void addVulnerability(Vulnerability vulnerability) {
        vulnerabilities.add(vulnerability);
    }

    public void removeVulnerability(Vulnerability vulnerability) {
        this.vulnerabilities.remove(vulnerability);
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
