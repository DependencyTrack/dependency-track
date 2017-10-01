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

import alpine.json.TrimmedStringArrayDeserializer;
import alpine.json.TrimmedStringDeserializer;
import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Serialized;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.UUID;

/**
 * Defines a Model class for tracking licenses.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class License implements Serializable {

    private static final long serialVersionUID = -1707920279688859358L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    /**
     * The String representation of the license name (i.e. Apache License 2.0).
     */
    @Persistent
    @Column(name = "NAME", allowsNull = "false")
    @JsonProperty(value = "name")
    @NotNull
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    private String name;

    /**
     * The contents of the license.
     */
    @Persistent
    @Column(name = "TEXT", jdbcType = "CLOB")
    @JsonProperty(value = "licenseText")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String text;

    /**
     * The standard license template typically used for the creation of the license text.
     */
    @Persistent
    @Column(name = "TEMPLATE", jdbcType = "CLOB")
    @JsonProperty(value = "standardLicenseTemplate")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String template;

    /**
     * The standard license header typically added to the top of source code.
     */
    @Persistent
    @Column(name = "HEADER", jdbcType = "CLOB")
    @JsonProperty(value = "standardLicenseHeader")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String header;

    /**
     * A comment about the license. Typically includes release date, etc.
     */
    @Persistent
    @Column(name = "COMMENT", jdbcType = "CLOB")
    @JsonProperty(value = "licenseComments")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String comment;

    /**
     * The SPDX defined licenseId (i.e. Apache-2.0).
     */
    @Persistent
    @Column(name = "LICENSEID")
    @Index(name = "LICENSE_LICENSEID_IDX")
    @JsonProperty(value = "licenseId")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.STRING_IDENTIFIER, message = "The licenseId may only contain alpha, numeric, and specific symbols _-.+")
    private String licenseId;

    /**
     * Identifies if the license is approved by the OSI.
     */
    @Persistent
    @Column(name = "ISOSIAPPROVED")
    @JsonProperty(value = "isOsiApproved")
    private boolean osiApproved;

    /**
     * Identifies if the licenseId has been deprecated by SPDX
     */
    @Persistent
    @Column(name = "ISDEPRECATED")
    @JsonProperty(value = "isDeprecatedLicenseId")
    private boolean deprecatedLicenseId;

    /**
     * The seeAlso field - may contain URLs to the original license info.
     */
    @Persistent(defaultFetchGroup = "true")
    @Serialized
    @Column(name = "SEEALSO")
    @JsonProperty(value = "seeAlso")
    @JsonDeserialize(using = TrimmedStringArrayDeserializer.class)
    private String[] seeAlso;

    @Persistent(customValueStrategy = "uuid")
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

    public boolean isDeprecatedLicenseId() {
        return deprecatedLicenseId;
    }

    public void setDeprecatedLicenseId(boolean deprecatedLicenseId) {
        this.deprecatedLicenseId = deprecatedLicenseId;
    }

    public String[] getSeeAlso() {
        return seeAlso;
    }

    public void setSeeAlso(String[] seeAlso) {
        this.seeAlso = seeAlso;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

}
