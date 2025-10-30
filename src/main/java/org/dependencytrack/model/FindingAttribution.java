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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;

import jakarta.validation.constraints.NotNull;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.Date;
import java.util.UUID;

/**
 * Model class for tracking the attribution of vulnerability identification.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@PersistenceCapable
@Index(name = "FINDINGATTRIBUTION_COMPOUND_IDX", members = {"component", "vulnerability"})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FindingAttribution implements Serializable {

    private static final long serialVersionUID = -2609603709255246845L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "ATTRIBUTED_ON", allowsNull = "false")
    @NotNull
    @Schema(type = "integer", format = "int64", requiredMode = Schema.RequiredMode.REQUIRED, description = "UNIX epoch timestamp in milliseconds")
    private Date attributedOn;

    @Persistent
    @Column(name = "ANALYZERIDENTITY", allowsNull = "false")
    private AnalyzerIdentity analyzerIdentity;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "COMPONENT_ID", allowsNull = "false")
    @NotNull
    private Component component;

    @Persistent(defaultFetchGroup = "false")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @NotNull
    private Project project;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "VULNERABILITY_ID", allowsNull = "false")
    @NotNull
    private Vulnerability vulnerability;

    @Persistent
    @Column(name = "ALT_ID", allowsNull = "true")
    private String alternateIdentifier;

    @Persistent
    @Column(name = "REFERENCE_URL", allowsNull = "true")
    private String referenceUrl;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "FINDINGATTRIBUTION_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public FindingAttribution() {}

    public FindingAttribution(Component component, Vulnerability vulnerability, AnalyzerIdentity analyzerIdentity,
                              String alternateIdentifier, String referenceUrl) {
        this.component = component;
        this.project = component.getProject();
        this.vulnerability = vulnerability;
        this.analyzerIdentity = analyzerIdentity;
        this.attributedOn = new Date();
        this.alternateIdentifier = alternateIdentifier;
        this.referenceUrl = maybeTrimUrl(referenceUrl);
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Date getAttributedOn() {
        return attributedOn;
    }

    public void setAttributedOn(Date attributedOn) {
        this.attributedOn = attributedOn;
    }

    public AnalyzerIdentity getAnalyzerIdentity() {
        return analyzerIdentity;
    }

    public void setAnalyzerIdentity(AnalyzerIdentity analyzerIdentity) {
        this.analyzerIdentity = analyzerIdentity;
    }

    public Component getComponent() {
        return component;
    }

    public void setComponent(Component component) {
        this.component = component;
        this.project = component.getProject();
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    public String getAlternateIdentifier() {
        return alternateIdentifier;
    }

    public void setAlternateIdentifier(String alternateIdentifier) {
        this.alternateIdentifier = alternateIdentifier;
    }

    public String getReferenceUrl() {
        return referenceUrl;
    }

    public void setReferenceUrl(String referenceUrl) {
        this.referenceUrl = maybeTrimUrl(referenceUrl);
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    private static String maybeTrimUrl(final String url) {
        if (url == null || url.length() <= 255) {
            return url;
        }

        final String[] parts = url.split("\\?", 2);
        if (parts.length == 2 && parts[0].length() <= 255) {
            return parts[0];
        }

        return parts[0].substring(0, 255);
    }

}
