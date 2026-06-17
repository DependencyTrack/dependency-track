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
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;

import jakarta.validation.constraints.NotNull;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.Extensions;
import javax.jdo.annotations.ForeignKey;
import javax.jdo.annotations.ForeignKeyAction;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.math.BigDecimal;
import java.util.List;

/**
 * The Analysis model tracks human auditing decisions for vulnerabilities found
 * on a given dependency.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable
@Unique(name="ANALYSIS_COMPOSITE_IDX", members={"project", "component", "vulnerability"})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Analysis implements Serializable {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @ForeignKey(name = "ANALYSIS_PROJECT_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "PROJECT_ID")
    @JsonIgnore
    private Project project;

    @Persistent(defaultFetchGroup = "true")
    @ForeignKey(name = "ANALYSIS_COMPONENT_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "COMPONENT_ID")
    @JsonIgnore
    private Component component;

    @Persistent(defaultFetchGroup = "true")
    @ForeignKey(name = "ANALYSIS_VULNERABILITY_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "VULNERABILITY_ID", allowsNull = "false")
    @NotNull
    @JsonIgnore
    private Vulnerability vulnerability;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "STATE", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    private AnalysisState analysisState;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "JUSTIFICATION", jdbcType = "VARCHAR", allowsNull = "true")
    @NotNull
    private AnalysisJustification analysisJustification;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "RESPONSE", jdbcType = "VARCHAR", allowsNull = "true")
    @NotNull
    private AnalysisResponse analysisResponse;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "DETAILS", jdbcType = "CLOB", allowsNull = "true")
    @NotNull
    private String analysisDetails;

    @Persistent(mappedBy = "analysis", defaultFetchGroup = "true")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "timestamp ASC, id ASC"))
    private List<AnalysisComment> analysisComments;

    @Persistent
    @Column(name = "SUPPRESSED")
    @JsonProperty(value = "isSuppressed")
    private boolean suppressed;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "SEVERITY")
    @Extensions(value = {
            @Extension(vendorName = "datanucleus", key = "insert-function", value = "CAST(? AS severity)"),
            @Extension(vendorName = "datanucleus", key = "update-function", value = "CAST(? AS severity)")
    })
    @JsonProperty(value = "severity")
    private Severity severity;

    @Persistent
    @Column(name = "CVSSV2VECTOR")
    @JsonProperty(value = "cvssV2Vector")
    private String cvssV2Vector;

    @Persistent
    @Column(name = "CVSSV2SCORE")
    @JsonProperty(value = "cvssV2Score")
    private BigDecimal cvssV2Score;

    @Persistent
    @Column(name = "CVSSV3VECTOR")
    @JsonProperty(value = "cvssV3Vector")
    private String cvssV3Vector;

    @Persistent
    @Column(name = "CVSSV3SCORE")
    @JsonProperty(value = "cvssV3Score")
    private BigDecimal cvssV3Score;

    @Persistent
    @Column(name = "CVSSV4VECTOR")
    @JsonProperty(value = "cvssV4Vector")
    private String cvssV4Vector;

    @Persistent
    @Column(name = "CVSSV4SCORE")
    @JsonProperty(value = "cvssV4Score")
    private BigDecimal cvssV4Score;

    @Persistent
    @Column(name = "OWASPVECTOR")
    @JsonProperty(value = "owaspVector")
    private String owaspVector;

    @Persistent
    @Column(name = "OWASPSCORE")
    @JsonProperty(value = "owaspScore")
    private BigDecimal owaspScore;

    @Persistent
    @Column(name = "VULNERABILITY_POLICY_ID", allowsNull = "true")
    @JsonIgnore
    private Long vulnerabilityPolicyId;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Project getProject() {
        return project;
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

    public AnalysisState getAnalysisState() {
        return analysisState;
    }

    public void setAnalysisState(AnalysisState analysisState) {
        this.analysisState = analysisState;
    }

    public AnalysisJustification getAnalysisJustification() {
        return analysisJustification;
    }

    public void setAnalysisJustification(AnalysisJustification analysisJustification) {
        this.analysisJustification = analysisJustification;
    }

    public AnalysisResponse getAnalysisResponse() {
        return analysisResponse;
    }

    public void setAnalysisResponse(AnalysisResponse analysisResponse) {
        this.analysisResponse = analysisResponse;
    }

    public String getAnalysisDetails() {
        return analysisDetails;
    }

    public void setAnalysisDetails(String analysisDetails) {
        this.analysisDetails = analysisDetails;
    }

    public List<AnalysisComment> getAnalysisComments() {
        return analysisComments;
    }

    public void setAnalysisComments(List<AnalysisComment> analysisComments) {
        this.analysisComments = analysisComments;
    }

    public boolean isSuppressed() {
        return suppressed;
    }

    public void setSuppressed(boolean suppressed) {
        this.suppressed = suppressed;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getCvssV2Vector() {
        return cvssV2Vector;
    }

    public void setCvssV2Vector(String cvssV2Vector) {
        this.cvssV2Vector = cvssV2Vector;
    }

    public BigDecimal getCvssV2Score() {
        return cvssV2Score;
    }

    public void setCvssV2Score(BigDecimal cvssV2Score) {
        this.cvssV2Score = cvssV2Score;
    }

    public String getCvssV3Vector() {
        return cvssV3Vector;
    }

    public void setCvssV3Vector(String cvssV3Vector) {
        this.cvssV3Vector = cvssV3Vector;
    }

    public BigDecimal getCvssV3Score() {
        return cvssV3Score;
    }

    public void setCvssV3Score(BigDecimal cvssV3Score) {
        this.cvssV3Score = cvssV3Score;
    }

    public String getCvssV4Vector() {
        return cvssV4Vector;
    }

    public void setCvssV4Vector(String cvssV4Vector) {
        this.cvssV4Vector = cvssV4Vector;
    }

    public BigDecimal getCvssV4Score() {
        return cvssV4Score;
    }

    public void setCvssV4Score(BigDecimal cvssV4Score) {
        this.cvssV4Score = cvssV4Score;
    }

    public String getOwaspVector() {
        return owaspVector;
    }

    public void setOwaspVector(String owaspVector) {
        this.owaspVector = owaspVector;
    }

    public BigDecimal getOwaspScore() {
        return owaspScore;
    }

    public void setOwaspScore(BigDecimal owaspScore) {
        this.owaspScore = owaspScore;
    }

    public Long getVulnerabilityPolicyId() {
        return vulnerabilityPolicyId;
    }

    public void setVulnerabilityPolicyId(Long vulnerabilityPolicyId) {
        this.vulnerabilityPolicyId = vulnerabilityPolicyId;
    }
}
