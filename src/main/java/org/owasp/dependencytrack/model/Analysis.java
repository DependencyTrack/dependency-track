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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Collection;

@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Analysis implements Serializable {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "DEPENDENCY_ID", allowsNull = "false")
    @NotNull
    private Dependency dependency;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "VULNERABILITY_ID", allowsNull = "false")
    @NotNull
    private Vulnerability vulnerability;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "STATE", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    private AnalysisState analysisState;

    @Persistent(mappedBy = "analysis")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "timestamp ASC"))
    private Collection<AnalysisComment> analysisComments;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Dependency getDependency() {
        return dependency;
    }

    public void setDependency(Dependency dependency) {
        this.dependency = dependency;
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

    public Collection<AnalysisComment> getAnalysisComments() {
        return analysisComments;
    }

    public void setAnalysisComments(Collection<AnalysisComment> analysisComments) {
        this.analysisComments = analysisComments;
    }
}