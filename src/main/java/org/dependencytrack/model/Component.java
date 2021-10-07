/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.model;

import alpine.json.TrimmedStringDeserializer;
import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.resources.v1.serializers.CustomPackageURLSerializer;
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
import javax.jdo.annotations.Serialized;
import javax.jdo.annotations.Unique;
import javax.json.JsonObject;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.ArrayList;
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
                @Persistent(name = "project"),
                @Persistent(name = "resolvedLicense"),
                @Persistent(name = "externalReferences"),
                @Persistent(name = "parent"),
                @Persistent(name = "children"),
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
    @Column(name = "AUTHOR", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The author may only contain printable characters")
    private String author;

    @Persistent
    @Column(name = "PUBLISHER", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The publisher may only contain printable characters")
    private String publisher;

    @Persistent
    @Column(name = "GROUP", jdbcType = "VARCHAR")
    @Index(name = "COMPONENT_GROUP_IDX")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The group may only contain printable characters")
    private String group;

    @Persistent
    @Column(name = "NAME", jdbcType = "VARCHAR", allowsNull = "false")
    @Index(name = "COMPONENT_NAME_IDX")
    @NotBlank
    @Size(min = 1, max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    private String name;

    @Persistent
    @Column(name = "VERSION", jdbcType = "VARCHAR")
    @Size(max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The version may only contain printable characters")
    private String version;

    @Persistent
    @Column(name = "CLASSIFIER", jdbcType = "VARCHAR")
    @Index(name = "COMPONENT_CLASSIFIER_IDX")
    @Extension(vendorName = "datanucleus", key = "enum-check-constraint", value = "true")
    private Classifier classifier;

    @Persistent
    @Column(name = "FILENAME", jdbcType = "VARCHAR")
    @Size(max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.FS_DIRECTORY_NAME, message = "The specified filename is not valid and cannot be used as a filename")
    private String filename;

    @Persistent
    @Column(name = "EXTENSION", jdbcType = "VARCHAR")
    @Size(max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
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
    @Index(name = "COMPONENT_SHA384_IDX")
    @Column(name = "SHA_384", jdbcType = "VARCHAR", length = 96)
    @Pattern(regexp = RegexSequence.Definition.HASH_SHA384, message = "The SHA-384 hash must be a valid 96 character HEX number")
    private String sha384;

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
    @Index(name = "COMPONENT_SHA3_384_IDX")
    @Column(name = "SHA3_384", jdbcType = "VARCHAR", length = 96)
    @Pattern(regexp = RegexSequence.Definition.HASH_SHA384, message = "The SHA3-384 hash must be a valid 96 character HEX number")
    private String sha3_384;

    @Persistent
    @Index(name = "COMPONENT_SHA3_512_IDX")
    @Column(name = "SHA3_512", jdbcType = "VARCHAR", length = 128)
    @Pattern(regexp = RegexSequence.Definition.HASH_SHA512, message = "The SHA3-512 hash must be a valid 128 character HEX number")
    private String sha3_512;

    @Persistent
    @Index(name = "COMPONENT_BLAKE2B_256_IDX")
    @Column(name = "BLAKE2B_256", jdbcType = "VARCHAR", length = 64)
    @Pattern(regexp = RegexSequence.Definition.HASH_SHA256, message = "The BLAKE2b hash must be a valid 64 character HEX number")
    private String blake2b_256;

    @Persistent
    @Index(name = "COMPONENT_BLAKE2B_384_IDX")
    @Column(name = "BLAKE2B_384", jdbcType = "VARCHAR", length = 96)
    @Pattern(regexp = RegexSequence.Definition.HASH_SHA384, message = "The BLAKE2b hash must be a valid 96 character HEX number")
    private String blake2b_384;

    @Persistent
    @Index(name = "COMPONENT_BLAKE2B_512_IDX")
    @Column(name = "BLAKE2B_512", jdbcType = "VARCHAR", length = 128)
    @Pattern(regexp = RegexSequence.Definition.HASH_SHA512, message = "The BLAKE2b hash must be a valid 128 character HEX number")
    private String blake2b_512;

    @Persistent
    @Index(name = "COMPONENT_BLAKE3_IDX")
    @Column(name = "BLAKE3", jdbcType = "VARCHAR", length = 255)
    @Pattern(regexp = RegexSequence.Definition.HEXADECIMAL, message = "The BLAKE3 hash must be a valid HEX number")
    private String blake3;

    @Persistent
    @Index(name = "COMPONENT_CPE_IDX")
    @Size(max = 255)
    //Patterns obtained from https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd
    @Pattern(regexp = "(cpe:2\\.3:[aho\\*\\-](:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|}~]))+(\\?*|\\*?))|[\\*\\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\\*\\-]))(:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|}~]))+(\\?*|\\*?))|[\\*\\-])){4})|([c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9\\._\\-~%]*){0,6})", message = "The CPE must conform to the CPE v2.2 or v2.3 specification defined by NIST")
    private String cpe;

    @Persistent(defaultFetchGroup = "true")
    @Index(name = "COMPONENT_PURL_IDX")
    @Size(max = 255)
    @com.github.packageurl.validator.PackageURL
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String purl;

    @Persistent(defaultFetchGroup = "true")
    @Index(name = "COMPONENT_PURL_COORDINATES_IDX")
    @Size(max = 255)
    @com.github.packageurl.validator.PackageURL
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String purlCoordinates; // Field should contain only type, namespace, name, and version. Everything up to the qualifiers

    @Persistent
    @Index(name = "COMPONENT_SWID_TAGID_IDX")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The SWID tagId may only contain printable characters")
    private String swidTagId;

    @Persistent
    @Column(name = "INTERNAL", allowsNull = "true")
    @JsonProperty("isInternal")
    private Boolean internal;

    @Persistent
    @Column(name = "DESCRIPTION", jdbcType = "VARCHAR", length = 1024)
    @Size(max = 1024)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The description may only contain printable characters")
    private String description;

    @Persistent
    @Column(name = "COPYRIGHT", jdbcType = "VARCHAR", length = 1024)
    @Size(max = 1024)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The copyright may only contain printable characters")
    private String copyright;

    @Persistent
    @Column(name = "LICENSE", jdbcType = "VARCHAR")
    @Size(max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The license may only contain printable characters")
    private String license;

    @Persistent(defaultFetchGroup = "true", cacheable = "false")
    @Column(name = "LICENSE_ID")
    private License resolvedLicense;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "DIRECT_DEPENDENCIES", jdbcType = "CLOB")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String directDependencies; // This will be a JSON string

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "EXTERNAL_REFERENCES")
    @Serialized
    private List<ExternalReference> externalReferences;

    @Persistent
    @Column(name = "PARENT_COMPONENT_ID")
    private Component parent;

    @Persistent(mappedBy = "parent")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private Collection<Component> children;

    @Persistent(table = "COMPONENTS_VULNERABILITIES")
    @Join(column = "COMPONENT_ID")
    @Element(column = "VULNERABILITY_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private List<Vulnerability> vulnerabilities;

    @Persistent(defaultFetchGroup = "true")
    @Index(name = "COMPONENT_PROJECT_ID_IDX")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @NotNull
    private Project project;

    /**
     * Convenience field which stores the Inherited Risk Score (IRS) of the last metric in the {@link DependencyMetrics} table
     */
    @Persistent
    @Index(name = "COMPONENT_LAST_RISKSCORE_IDX")
    @Column(name = "LAST_RISKSCORE", allowsNull = "true") // New column, must allow nulls on existing databases))
    private Double lastInheritedRiskScore;

    /**
     * Sticky notes
     */
    @Persistent(defaultFetchGroup = "true")
    @Column(name = "TEXT", jdbcType = "CLOB")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String notes;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "COMPONENT_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    private transient String bomRef;
    private transient DependencyMetrics metrics;
    private transient RepositoryMetaComponent repositoryMeta;
    private transient int usedBy;

    @JsonIgnore
    private transient JsonObject cacheResult;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public String getPublisher() {
        return publisher;
    }

    public void setPublisher(String publisher) {
        this.publisher = publisher;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(String group) {
        this.group = StringUtils.abbreviate(group, 255);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = StringUtils.abbreviate(name, 255);
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = StringUtils.abbreviate(version, 255);
    }

    public Classifier getClassifier() {
        return classifier;
    }

    public void setClassifier(Classifier classifier) {
        this.classifier = classifier;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = StringUtils.abbreviate(filename, 255);
    }

    public String getExtension() {
        return extension;
    }

    public void setExtension(String extension) {
        this.extension = StringUtils.abbreviate(extension, 255);
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

    public String getSha384() {
        return sha384;
    }

    public void setSha384(String sha384) {
        this.sha384 = sha384;
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

    public String getSha3_384() {
        return sha3_384;
    }

    public void setSha3_384(String sha3_384) {
        this.sha3_384 = sha3_384;
    }

    public String getSha3_512() {
        return sha3_512;
    }

    public void setSha3_512(String sha3_512) {
        this.sha3_512 = sha3_512;
    }

    public String getBlake2b_256() {
        return blake2b_256;
    }

    public void setBlake2b_256(String blake2b_256) {
        this.blake2b_256 = blake2b_256;
    }

    public String getBlake2b_384() {
        return blake2b_384;
    }

    public void setBlake2b_384(String blake2b_384) {
        this.blake2b_384 = blake2b_384;
    }

    public String getBlake2b_512() {
        return blake2b_512;
    }

    public void setBlake2b_512(String blake2b_512) {
        this.blake2b_512 = blake2b_512;
    }

    public String getBlake3() {
        return blake3;
    }

    public void setBlake3(String blake3) {
        this.blake3 = blake3;
    }

    public String getCpe() {
        return cpe;
    }

    public void setCpe(String cpe) {
        this.cpe = StringUtils.abbreviate(cpe, 255);
    }

    @JsonSerialize(using = CustomPackageURLSerializer.class)
    public PackageURL getPurl() {
        if (purl == null) {
            return null;
        }
        try {
            return new PackageURL(purl);
        } catch (MalformedPackageURLException e) {
            return null;
        }
    }

    public void setPurl(PackageURL purl) {
        if (purl != null) {
            this.purl = purl.canonicalize();
        } else {
            this.purl = null;
        }
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }

    @JsonSerialize(using = CustomPackageURLSerializer.class)
    public PackageURL getPurlCoordinates() {
        if (purlCoordinates == null) {
            return null;
        }
        try {
            return new PackageURL(purlCoordinates);
        } catch (MalformedPackageURLException e) {
            return null;
        }
    }

    public void setPurlCoordinates(PackageURL purlCoordinates) {
        if (purlCoordinates != null) {
            this.purlCoordinates = purlCoordinates.canonicalize();
        } else {
            this.purlCoordinates = null;
        }
    }

    public void setPurlCoordinates(String purlCoordinates) {
        this.purlCoordinates = purlCoordinates;
    }

    public String getSwidTagId() {
        return swidTagId;
    }

    public void setSwidTagId(String swidTagId) {
        this.swidTagId = swidTagId;
    }

    public boolean isInternal() {
        if (internal == null) {
            return false;
        }
        return internal;
    }

    public void setInternal(boolean internal) {
        this.internal = internal;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = StringUtils.abbreviate(description, 1024);
    }

    public String getCopyright() {
        return copyright;
    }

    public void setCopyright(String copyright) {
        this.copyright = StringUtils.abbreviate(copyright, 1024);
    }

    public String getLicense() {
        return license;
    }

    public void setLicense(String license) {
        this.license = StringUtils.abbreviate(license, 255);
    }

    public License getResolvedLicense() {
        return resolvedLicense;
    }

    public void setResolvedLicense(License resolvedLicense) {
        this.resolvedLicense = resolvedLicense;
    }

    public String getDirectDependencies() {
        return directDependencies;
    }

    public void setDirectDependencies(String directDependencies) {
        this.directDependencies = directDependencies;
    }

    public List<ExternalReference> getExternalReferences() {
        return externalReferences;
    }

    public void addExternalReference(ExternalReference externalReferences) {
        if (this.externalReferences == null) {
            this.externalReferences = new ArrayList<>();
        }
        this.externalReferences.add(externalReferences);
    }

    public void setExternalReferences(List<ExternalReference> externalReferences) {
        this.externalReferences = externalReferences;
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

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public void addVulnerability(Vulnerability vulnerability) {
        if (vulnerabilities == null) {
            vulnerabilities = new ArrayList<>();
        }
        vulnerabilities.add(vulnerability);
    }

    public void removeVulnerability(Vulnerability vulnerability) {
        this.vulnerabilities.remove(vulnerability);
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public DependencyMetrics getMetrics() {
        return metrics;
    }

    public void setMetrics(DependencyMetrics metrics) {
        this.metrics = metrics;
    }

    public RepositoryMetaComponent getRepositoryMeta() {
        return repositoryMeta;
    }

    public void setRepositoryMeta(RepositoryMetaComponent repositoryMeta) {
        this.repositoryMeta = repositoryMeta;
    }

    public Double getLastInheritedRiskScore() {
        return lastInheritedRiskScore;
    }

    public void setLastInheritedRiskScore(Double lastInheritedRiskScore) {
        this.lastInheritedRiskScore = lastInheritedRiskScore;
    }

    public String getBomRef() {
        return bomRef;
    }

    public void setBomRef(String bomRef) {
        this.bomRef = bomRef;
    }

    public int getUsedBy() {
        return usedBy;
    }

    public void setUsedBy(int usedBy) {
        this.usedBy = usedBy;
    }

    public JsonObject getCacheResult() {
        return cacheResult;
    }

    public void setCacheResult(JsonObject cacheResult) {
        this.cacheResult = cacheResult;
    }

    @Override
    public String toString() {
        if (getPurl() != null) {
            return getPurl().canonicalize();
        } else {
            StringBuilder sb = new StringBuilder();
            if (getGroup() != null) {
                sb.append(getGroup()).append(" : ");
            }
            sb.append(getName());
            if (getVersion() != null) {
                sb.append(" : ").append(getVersion());
            }
            return sb.toString();
        }
    }
}
