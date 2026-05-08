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
import jakarta.validation.constraints.NotNull;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.ForeignKey;
import javax.jdo.annotations.ForeignKeyAction;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import java.io.Serializable;
import java.util.Date;

/**
 * Model class for tracking the attribution of vulnerability identification.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@PersistenceCapable
@Index(name = "FINDINGATTRIBUTION_COMPOUND_IDX", members = {"component", "vulnerability", "analyzerIdentity"}, unique = "true")
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
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private Date attributedOn;

    @Persistent
    @Column(name = "ANALYZERIDENTITY", allowsNull = "false")
    private String analyzerIdentity;

    @Persistent(defaultFetchGroup = "true")
    @ForeignKey(name = "FINDINGATTRIBUTION_COMPONENT_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "COMPONENT_ID", allowsNull = "false")
    @NotNull
    private Component component;

    @Persistent(defaultFetchGroup = "false")
    @ForeignKey(name = "FINDINGATTRIBUTION_PROJECT_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @NotNull
    private Project project;

    @Persistent(defaultFetchGroup = "true")
    @ForeignKey(name = "FINDINGATTRIBUTION_VULNERABILITY_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "VULNERABILITY_ID", allowsNull = "false")
    @NotNull
    private Vulnerability vulnerability;

    /**
     * The percentage of this match ranging from 0...100.
     */
    @Persistent
    @Column(name = "MATCHING_PERCENTAGE", allowsNull = "true")
    private Short matchingPercentage;

    @Persistent
    @Column(name = "ALT_ID", allowsNull = "true")
    private String alternateIdentifier;

    @Persistent
    @Column(name = "REFERENCE_URL", allowsNull = "true")
    private String referenceUrl;

    @Persistent
    @Column(name = "DELETED_AT", allowsNull = "true")
    @JsonIgnore
    private Date deletedAt;

    public FindingAttribution() {}

    public FindingAttribution(
            Component component,
            Vulnerability vulnerability,
            String analyzerIdentity,
            String alternateIdentifier,
            String referenceUrl) {
        this.component = component;
        this.project = component.getProject();
        this.vulnerability = vulnerability;
        this.analyzerIdentity = analyzerIdentity;
        this.attributedOn = new Date();
        this.alternateIdentifier = alternateIdentifier;
        this.referenceUrl = referenceUrl;
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

    public String getAnalyzerIdentity() {
        return analyzerIdentity;
    }

    public void setAnalyzerIdentity(String analyzerIdentity) {
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

    public Short getMatchingPercentage() {
        return matchingPercentage;
    }

    public void setMatchingPercentage(Short matchingPercentage) {
        this.matchingPercentage = matchingPercentage;
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
        this.referenceUrl = referenceUrl;
    }

    public Date getDeletedAt() {
        return deletedAt;
    }

    public void setDeletedAt(Date deletedAt) {
        this.deletedAt = deletedAt;
    }

}
