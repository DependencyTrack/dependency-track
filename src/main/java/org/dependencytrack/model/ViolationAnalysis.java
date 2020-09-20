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
 * The ViolationAnalysis model tracks human auditing decisions for policy violations.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@PersistenceCapable
@Unique(name="VIOLATIONANALYSIS_COMPOSITE_IDX", members={"project", "component", "policyViolation"})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ViolationAnalysis implements Serializable {

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
    @Column(name = "POLICYVIOLATION_ID", allowsNull = "false")
    @NotNull
    @JsonIgnore
    private PolicyViolation policyViolation;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "STATE", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    private ViolationAnalysisState analysisState;

    @Persistent(mappedBy = "violationAnalysis", defaultFetchGroup = "true")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "timestamp ASC"))
    private List<ViolationAnalysisComment> analysisComments;

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

    public PolicyViolation getPolicyViolation() {
        return policyViolation;
    }

    public void setPolicyViolation(PolicyViolation policyViolation) {
        this.policyViolation = policyViolation;
    }

    public ViolationAnalysisState getAnalysisState() {
        return analysisState;
    }

    public void setViolationAnalysisState(ViolationAnalysisState analysisState) {
        this.analysisState = analysisState;
    }

    public List<ViolationAnalysisComment> getAnalysisComments() {
        return analysisComments;
    }

    public void setAnalysisComments(List<ViolationAnalysisComment> analysisComments) {
        this.analysisComments = analysisComments;
    }

    public boolean isSuppressed() {
        return suppressed;
    }

    public void setSuppressed(boolean suppressed) {
        this.suppressed = suppressed;
    }
}
