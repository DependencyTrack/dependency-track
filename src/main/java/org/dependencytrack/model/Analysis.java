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
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
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
    @Column(name = "PROJECT_ID")
    @JsonIgnore
    private Project project;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "COMPONENT_ID")
    @JsonIgnore
    private Component component;

    @Persistent(defaultFetchGroup = "true")
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
    @Column(name = "DETAILS", jdbcType = "VARCHAR", allowsNull = "true")
    @NotNull
    private String analysisDetails;

    @Persistent(mappedBy = "analysis", defaultFetchGroup = "true")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "timestamp ASC"))
    private List<AnalysisComment> analysisComments;

    @Persistent
    @Column(name = "SUPPRESSED")
    @JsonProperty(value = "isSuppressed")
    private boolean suppressed;

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
}
