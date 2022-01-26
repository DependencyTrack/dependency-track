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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
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
@Index(name = "VULNERABLESOFTWARE_CPE23_VERSION_RANGE_IDX", members = {"cpe23", "versionEndExcluding", "versionEndIncluding", "versionStartExcluding", "versionStartIncluding"})
@Index(name = "VULNERABLESOFTWARE_PART_VENDOR_PRODUCT_IDX", members = {"part", "vendor", "product"})
@Index(name = "VULNERABLESOFTWARE_CPE_PURL_PARTS_IDX", members = {"part", "vendor", "product", "purlType", "purlNamespace", "purlName"})
@Index(name = "VULNERABLESOFTWARE_PURL_VERSION_RANGE_IDX", members = {"purl", "versionEndExcluding", "versionEndIncluding", "versionStartExcluding", "versionStartIncluding"})
@Index(name = "VULNERABLESOFTWARE_PURL_TYPE_NS_NAME_IDX", members = {"purlType", "purlNamespace", "purlName"})
public class VulnerableSoftware implements ICpe, Serializable {

    private static final long serialVersionUID = -3987946408457131098L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "PURL", jdbcType = "VARCHAR")
    private String purl;

    @Persistent
    @Column(name = "PURL_TYPE", jdbcType = "VARCHAR")
    private String purlType;

    @Persistent
    @Column(name = "PURL_NAMESPACE", jdbcType = "VARCHAR")
    private String purlNamespace;

    @Persistent
    @Column(name = "PURL_NAME", jdbcType = "VARCHAR")
    private String purlName;

    @Persistent
    @Column(name = "PURL_VERSION", jdbcType = "VARCHAR")
    private String purlVersion;

    @Persistent
    @Column(name = "PURL_QUALIFIERS", jdbcType = "VARCHAR")
    private String purlQualifiers;

    @Persistent
    @Column(name = "PURL_SUBPATH", jdbcType = "VARCHAR")
    private String purlSubpath;

    @Persistent
    @Column(name = "CPE22", jdbcType = "VARCHAR")
    private String cpe22;

    @Persistent
    @Column(name = "CPE23", jdbcType = "VARCHAR")
    private String cpe23;

    @Persistent
    @Column(name = "PART", jdbcType = "VARCHAR")
    private String part;

    @Persistent
    @Column(name = "VENDOR", jdbcType = "VARCHAR")
    private String vendor;

    @Persistent
    @Column(name = "PRODUCT", jdbcType = "VARCHAR")
    private String product;

    @Persistent
    private String version;

    @Persistent
    @Column(name = "UPDATE", jdbcType = "VARCHAR")
    private String update;

    @Persistent
    @Column(name = "EDITION", jdbcType = "VARCHAR")
    private String edition;

    @Persistent
    @Column(name = "LANGUAGE", jdbcType = "VARCHAR")
    private String language;

    @Persistent
    @Column(name = "SWEDITION", jdbcType = "VARCHAR")
    private String swEdition;

    @Persistent
    @Column(name = "TARGETSW", jdbcType = "VARCHAR")
    private String targetSw;

    @Persistent
    @Column(name = "TARGETHW", jdbcType = "VARCHAR")
    private String targetHw;

    @Persistent
    @Column(name = "OTHER", jdbcType = "VARCHAR")
    private String other;

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

    @Persistent(table = "VULNERABLESOFTWARE_VULNERABILITIES", mappedBy = "vulnerableSoftware")
    @Join(column = "VULNERABLESOFTWARE_ID")
    @Element(column = "VULNERABILITY_ID", dependent = "false")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private List<Vulnerability> vulnerabilities;

    @Persistent(defaultFetchGroup = "true", customValueStrategy = "uuid")
    @Unique(name = "VULNERABLESOFTWARE_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getPurl() {
        return purl;
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }

    public String getPurlType() {
        return purlType;
    }

    public void setPurlType(String purlType) {
        this.purlType = purlType;
    }

    public String getPurlNamespace() {
        return purlNamespace;
    }

    public void setPurlNamespace(String purlNamespace) {
        this.purlNamespace = purlNamespace;
    }

    public String getPurlName() {
        return purlName;
    }

    public void setPurlName(String purlName) {
        this.purlName = purlName;
    }

    public String getPurlVersion() {
        return purlVersion;
    }

    public void setPurlVersion(String purlVersion) {
        this.purlVersion = purlVersion;
    }

    public String getPurlQualifiers() {
        return purlQualifiers;
    }

    public void setPurlQualifiers(String purlQualifiers) {
        this.purlQualifiers = purlQualifiers;
    }

    public String getPurlSubpath() {
        return purlSubpath;
    }

    public void setPurlSubpath(String purlSubpath) {
        this.purlSubpath = purlSubpath;
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

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public void addVulnerability(Vulnerability vulnerability) {
        if (this.vulnerabilities == null) {
            this.vulnerabilities = new ArrayList<>();
        }
        this.vulnerabilities.add(vulnerability);
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
