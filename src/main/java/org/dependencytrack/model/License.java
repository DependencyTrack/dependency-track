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

import alpine.json.TrimmedStringArrayDeserializer;
import alpine.json.TrimmedStringDeserializer;
import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.FetchGroup;
import javax.jdo.annotations.FetchGroups;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Serialized;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.List;
import java.util.UUID;

/**
 * Defines a Model class for tracking licenses.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable
@FetchGroups({
        @FetchGroup(name = "ALL", members = {
                @Persistent(name = "name"),
                @Persistent(name = "text"),
                @Persistent(name = "template"),
                @Persistent(name = "header"),
                @Persistent(name = "comment"),
                @Persistent(name = "licenseId"),
                @Persistent(name = "osiApproved"),
                @Persistent(name = "fsfLibre"),
                @Persistent(name = "deprecatedLicenseId"),
                @Persistent(name = "seeAlso"),
                @Persistent(name = "licenseGroups"),
                @Persistent(name = "uuid"),
        }),
        @FetchGroup(name = "CONCISE", members = {
                @Persistent(name = "name"),
                @Persistent(name = "licenseId"),
                @Persistent(name = "osiApproved"),
                @Persistent(name = "fsfLibre"),
        })
})
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class License implements Serializable {

    /**
     * Defines names of JDO fetch groups for this class.
     */
    public enum FetchGroup {
        ALL,
        CONCISE
    }

    private static final long serialVersionUID = -1707920279688859358L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    /**
     * The String representation of the license name (i.e. Apache License 2.0).
     */
    @Persistent(defaultFetchGroup = "true")
    @Column(name = "NAME", allowsNull = "false")
    @Index(name = "LICENSE_NAME_IDX")
    @JsonProperty(value = "name")
    @NotBlank
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    private String name;

    /**
     * The contents of the license.
     */
    @Persistent(defaultFetchGroup = "false")
    @Column(name = "TEXT", jdbcType = "CLOB")
    @JsonProperty(value = "licenseText")
    @JsonAlias(value = "licenseExceptionText")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String text;

    /**
     * The standard license template typically used for the creation of the license text.
     */
    @Persistent(defaultFetchGroup = "false")
    @Column(name = "TEMPLATE", jdbcType = "CLOB")
    @JsonProperty(value = "standardLicenseTemplate")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String template;

    /**
     * The standard license header typically added to the top of source code.
     */
    @Persistent(defaultFetchGroup = "false")
    @Column(name = "HEADER", jdbcType = "CLOB")
    @JsonProperty(value = "standardLicenseHeader")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String header;

    /**
     * A comment about the license. Typically includes release date, etc.
     */
    @Persistent(defaultFetchGroup = "false")
    @Column(name = "COMMENT", jdbcType = "CLOB")
    @JsonProperty(value = "licenseComments")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String comment;

    /**
     * The SPDX defined licenseId (i.e. Apache-2.0).
     */
    @Persistent(defaultFetchGroup = "true")
    @Column(name = "LICENSEID")
    @Index(name = "LICENSE_LICENSEID_IDX", unique = "true")
    @JsonProperty(value = "licenseId")
    @JsonAlias(value = "licenseExceptionId")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.STRING_IDENTIFIER, message = "The licenseId may only contain alpha, numeric, and specific symbols _-.+")
    private String licenseId;

    /**
     * Identifies if the license is approved by the OSI.
     */
    @Persistent(defaultFetchGroup = "true")
    @Column(name = "ISOSIAPPROVED")
    @JsonProperty(value = "isOsiApproved")
    private boolean osiApproved;

    /**
     * Identifies if the license is FSF Libre.
     */
    @Persistent(defaultFetchGroup = "true")
    @Column(name = "FSFLIBRE", allowsNull = "true") // New column, must allow nulls on existing databases
    @JsonProperty(value = "isFsfLibre")
    private boolean fsfLibre;

    /**
     * Identifies if the licenseId has been deprecated by SPDX
     */
    @Persistent(defaultFetchGroup = "false")
    @Column(name = "ISDEPRECATED")
    @JsonProperty(value = "isDeprecatedLicenseId")
    private boolean deprecatedLicenseId;

    /**
     * The seeAlso field - may contain URLs to the original license info.
     */
    @Persistent(defaultFetchGroup = "false")
    @Serialized
    @Column(name = "SEEALSO", jdbcType = "LONGVARBINARY")
    @JsonProperty(value = "seeAlso")
    @JsonDeserialize(using = TrimmedStringArrayDeserializer.class)
    private String[] seeAlso;

    /**
     * Specifies zero-to-n license groups this license is part of.
     */
    @Persistent(mappedBy = "licenses")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private List<LicenseGroup> licenseGroups;

    /**
     * The unique identifier of the object.
     */
    @Persistent(defaultFetchGroup = "true", customValueStrategy = "uuid")
    @Unique(name = "LICENSE_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getTemplate() {
        return template;
    }

    public void setTemplate(String template) {
        this.template = template;
    }

    public String getHeader() {
        return header;
    }

    public void setHeader(String header) {
        this.header = header;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getLicenseId() {
        return licenseId;
    }

    public void setLicenseId(String licenseId) {
        this.licenseId = licenseId;
    }

    public boolean isOsiApproved() {
        return osiApproved;
    }

    public void setOsiApproved(boolean osiApproved) {
        this.osiApproved = osiApproved;
    }

    public boolean isFsfLibre() {
        return fsfLibre;
    }

    public void setFsfLibre(boolean fsfLibre) {
        this.fsfLibre = fsfLibre;
    }

    public boolean isDeprecatedLicenseId() {
        return deprecatedLicenseId;
    }

    public void setDeprecatedLicenseId(boolean deprecatedLicenseId) {
        this.deprecatedLicenseId = deprecatedLicenseId;
    }

    public String[] getSeeAlso() {
        return seeAlso != null ? seeAlso.clone() : null;
    }

    public void setSeeAlso(String... seeAlso) {
        if (seeAlso != null) {
            this.seeAlso = seeAlso.clone();
        } else {
            this.seeAlso = null;
        }
    }

    public List<LicenseGroup> getLicenseGroups() {
        return licenseGroups;
    }

    public void setLicenseGroups(List<LicenseGroup> licenseGroups) {
        this.licenseGroups = licenseGroups;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

}
