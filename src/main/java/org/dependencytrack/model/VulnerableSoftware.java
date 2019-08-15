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

import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.UUID;

/**
 * The VulnerableSoftware is a model class for representing vulnerable software
 * as defined by CPE. In essence, it's a CPE which is directly associated to a
 * vulnerability through the NVD CVE data feeds.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VulnerableSoftware implements ICpe, Serializable {

    private static final long serialVersionUID = -3987946408457131098L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "CPE22", jdbcType = "VARCHAR")
    @Index(name = "VULNERABLESOFTWARE_CPE22_IDX")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The cpe22 may only contain printable characters")
    private String cpe22;

    @Persistent
    @Column(name = "CPE23", jdbcType = "VARCHAR", allowsNull = "false")
    @Index(name = "VULNERABLESOFTWARE_CPE23_IDX", unique = "true")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The cpe23 may only contain printable characters")
    private String cpe23;

    @Persistent
    @Column(name = "PART", jdbcType = "VARCHAR")
    @Size(max = 1)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The part may only contain printable characters")
    private String part;

    @Persistent
    @Column(name = "VENDOR", jdbcType = "VARCHAR")
    @Index(name = "VULNERABLESOFTWARE_VENDOR_IDX")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The vendor may only contain printable characters")
    private String vendor;

    @Persistent
    @Column(name = "PRODUCT", jdbcType = "VARCHAR")
    @Index(name = "VULNERABLESOFTWARE_PRODUCT_IDX")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The product may only contain printable characters")
    private String product;

    @Persistent
    @Column(name = "VERSION", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The version may only contain printable characters")
    private String version;

    @Persistent
    @Column(name = "UPDATE", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The update may only contain printable characters")
    private String update;

    @Persistent
    @Column(name = "EDITION", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The edition may only contain printable characters")
    private String edition;

    @Persistent
    @Column(name = "LANGUAGE", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The language may only contain printable characters")
    private String language;

    @Persistent
    @Column(name = "SWEDITION", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The swEdition may only contain printable characters")
    private String swEdition;

    @Persistent
    @Column(name = "TARGETSW", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The targetSw may only contain printable characters")
    private String targetSw;

    @Persistent
    @Column(name = "TARGETHW", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The targetHw may only contain printable characters")
    private String targetHw;

    @Persistent
    @Column(name = "OTHER", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The other may only contain printable characters")
    private String other;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "VULNERABILITY_ID")
    @Index(name = "VULNERABLESOFTWARE_VULNERABILITY_IDX")
    private Vulnerability vulnerability;

    @Persistent
    @Column(name = "VERSIONENDEXCLUDING")
    private String versionEndExcluding;

    @Persistent
    @Column(name = "VERSIONENDINCLUDING")
    private String versionEndIncluding;

    @Persistent
    @Column(name = "VERSIONSTARTEXCLUDING")
    private String versionStartExcluding;

    @Persistent
    @Column(name = "VERSIONSTARTINCLUDING")
    private String versionStartIncluding;

    @Persistent
    @Column(name = "VULNERABLE")
    @JsonProperty(value = "isVulnerable")
    private boolean vulnerable;

    @Persistent(defaultFetchGroup = "true", customValueStrategy = "uuid")
    @Unique(name = "VULNERABLESOFTWARE_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getCpe22() {
        return cpe22;
    }

    public void setCpe22(String cpe22) {
        this.cpe22 = cpe22;
    }

    public String getCpe23() {
        return cpe23;
    }

    public void setCpe23(String cpe23) {
        this.cpe23 = cpe23;
    }

    public String getPart() {
        return part;
    }

    public void setPart(String part) {
        this.part = part;
    }

    public String getVendor() {
        return vendor;
    }

    public void setVendor(String vendor) {
        this.vendor = vendor;
    }

    public String getProduct() {
        return product;
    }

    public void setProduct(String product) {
        this.product = product;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getUpdate() {
        return update;
    }

    public void setUpdate(String update) {
        this.update = update;
    }

    public String getEdition() {
        return edition;
    }

    public void setEdition(String edition) {
        this.edition = edition;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public String getSwEdition() {
        return swEdition;
    }

    public void setSwEdition(String swEdition) {
        this.swEdition = swEdition;
    }

    public String getTargetSw() {
        return targetSw;
    }

    public void setTargetSw(String targetSw) {
        this.targetSw = targetSw;
    }

    public String getTargetHw() {
        return targetHw;
    }

    public void setTargetHw(String targetHw) {
        this.targetHw = targetHw;
    }

    public String getOther() {
        return other;
    }

    public void setOther(String other) {
        this.other = other;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    public String getVersionEndExcluding() {
        return versionEndExcluding;
    }

    public void setVersionEndExcluding(String versionEndExcluding) {
        this.versionEndExcluding = versionEndExcluding;
    }

    public String getVersionEndIncluding() {
        return versionEndIncluding;
    }

    public void setVersionEndIncluding(String versionEndIncluding) {
        this.versionEndIncluding = versionEndIncluding;
    }

    public String getVersionStartExcluding() {
        return versionStartExcluding;
    }

    public void setVersionStartExcluding(String versionStartExcluding) {
        this.versionStartExcluding = versionStartExcluding;
    }

    public String getVersionStartIncluding() {
        return versionStartIncluding;
    }

    public void setVersionStartIncluding(String versionStartIncluding) {
        this.versionStartIncluding = versionStartIncluding;
    }

    public boolean isVulnerable() {
        return vulnerable;
    }

    public void setVulnerable(boolean vulnerable) {
        this.vulnerable = vulnerable;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
