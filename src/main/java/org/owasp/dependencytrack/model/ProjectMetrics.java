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
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;

/**
 * Metrics specific to individual projects.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProjectMetrics implements Serializable {

    private static final long serialVersionUID = 8741534340846353210L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @NotNull
    private Project project;

    @Persistent
    @Column(name = "CRITICAL")
    private int critical;

    @Persistent
    @Column(name = "HIGH")
    private int high;

    @Persistent
    @Column(name = "MEDIUM")
    private int medium;

    @Persistent
    @Column(name = "LOW")
    private int low;

    @Persistent
    @Column(name = "VULNERABILITIES")
    private int vulnerabilities;

    @Persistent
    @Column(name = "VULNERABLECOMPONENTS")
    private int vulnerableComponents;

    @Persistent
    @Column(name = "COMPONENTS")
    private int components;

    @Persistent
    @Column(name = "SUPPRESSED")
    private int suppressed;

    @Persistent
    @Column(name = "RISKSCORE")
    private double inheritedRiskScore;

    @Persistent
    @Column(name = "FIRST_OCCURRENCE", jdbcType = "TIMESTAMP", allowsNull = "false")
    @NotNull
    @Index(name = "PROJECTMETRICS_FIRST_OCCURRENCE_IDX")
    private Date firstOccurrence;

    @Persistent
    @Column(name = "LAST_OCCURRENCE", jdbcType = "TIMESTAMP", allowsNull = "false")
    @NotNull
    @Index(name = "PROJECTMETRICS_LAST_OCCURRENCE_IDX")
    private Date lastOccurrence;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public int getCritical() {
        return critical;
    }

    public void setCritical(int critical) {
        this.critical = critical;
    }

    public int getHigh() {
        return high;
    }

    public void setHigh(int high) {
        this.high = high;
    }

    public int getMedium() {
        return medium;
    }

    public void setMedium(int medium) {
        this.medium = medium;
    }

    public int getLow() {
        return low;
    }

    public void setLow(int low) {
        this.low = low;
    }

    public long getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(int vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public int getVulnerableComponents() {
        return vulnerableComponents;
    }

    public void setVulnerableComponents(int vulnerableComponents) {
        this.vulnerableComponents = vulnerableComponents;
    }

    public int getComponents() {
        return components;
    }

    public void setComponents(int components) {
        this.components = components;
    }

    public int getSuppressed() {
        return suppressed;
    }

    public void setSuppressed(int suppressed) {
        this.suppressed = suppressed;
    }

    public double getInheritedRiskScore() {
        return inheritedRiskScore;
    }

    public void setInheritedRiskScore(double inheritedRiskScore) {
        this.inheritedRiskScore = inheritedRiskScore;
    }

    public Date getFirstOccurrence() {
        return firstOccurrence;
    }

    public void setFirstOccurrence(Date firstOccurrence) {
        this.firstOccurrence = firstOccurrence;
    }

    public Date getLastOccurrence() {
        return lastOccurrence;
    }

    public void setLastOccurrence(Date lastOccurrence) {
        this.lastOccurrence = lastOccurrence;
    }
}
