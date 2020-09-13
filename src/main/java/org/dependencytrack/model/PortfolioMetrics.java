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
 * Metrics for the entire application as a whole, not specific to individual
 * components or projects.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PortfolioMetrics implements Serializable {

    private static final long serialVersionUID = -7690624184866776922L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

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
    @Column(name = "UNASSIGNED_SEVERITY", allowsNull = "true") // New column, must allow nulls on existing databases)
    private Integer unassigned;

    @Persistent
    @Column(name = "VULNERABILITIES")
    private int vulnerabilities;

    @Persistent
    @Column(name = "PROJECTS")
    private int projects;

    @Persistent
    @Column(name = "VULNERABLEPROJECTS")
    private int vulnerableProjects;

    @Persistent
    @Column(name = "COMPONENTS")
    private int components;

    @Persistent
    @Column(name = "VULNERABLECOMPONENTS")
    private int vulnerableComponents;

    @Persistent
    @Column(name = "SUPPRESSED")
    private int suppressed;

    @Persistent
    @Column(name = "FINDINGS_TOTAL", allowsNull = "true") // New column, must allow nulls on existing databases)
    private Integer findingsTotal;

    @Persistent
    @Column(name = "FINDINGS_AUDITED", allowsNull = "true") // New column, must allow nulls on existing databases)
    private Integer findingsAudited;

    @Persistent
    @Column(name = "FINDINGS_UNAUDITED", allowsNull = "true") // New column, must allow nulls on existing databases)
    private Integer findingsUnaudited;

    @Persistent
    @Column(name = "RISKSCORE")
    private double inheritedRiskScore;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_FAIL", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsFail;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_WARN", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsWarn;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_INFO", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsInfo;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_TOTAL", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsTotal;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_AUDITED", allowsNull = "true") // New column, must allow nulls on existing databases)
    private Integer policyViolationsAudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_UNAUDITED", allowsNull = "true") // New column, must allow nulls on existing databases)
    private Integer policyViolationsUnaudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_SECURITY_TOTAL", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsSecurityTotal;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_SECURITY_AUDITED", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsSecurityAudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_SECURITY_UNAUDITED", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsSecurityUnaudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_LICENSE_TOTAL", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsLicenseTotal;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_LICENSE_AUDITED", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsLicenseAudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_LICENSE_UNAUDITED", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsLicenseUnaudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_OPERATIONAL_TOTAL", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsOperationalTotal;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_OPERATIONAL_AUDITED", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsOperationalAudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsOperationalUnaudited;

    @Persistent
    @Column(name = "FIRST_OCCURRENCE", allowsNull = "false")
    @NotNull
    @Index(name = "PORTFOLIOMETRICS_FIRST_OCCURRENCE_IDX")
    private Date firstOccurrence;

    @Persistent
    @Column(name = "LAST_OCCURRENCE", allowsNull = "false")
    @NotNull
    @Index(name = "PORTFOLIOMETRICS_LAST_OCCURRENCE_IDX")
    private Date lastOccurrence;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
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

    public int getUnassigned() {
        return unassigned;
    }

    public void setUnassigned(int unassigned) {
        this.unassigned = unassigned;
    }

    public int getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(int vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public int getProjects() {
        return projects;
    }

    public void setProjects(int projects) {
        this.projects = projects;
    }

    public int getVulnerableProjects() {
        return vulnerableProjects;
    }

    public void setVulnerableProjects(int vulnerableProjects) {
        this.vulnerableProjects = vulnerableProjects;
    }

    public int getComponents() {
        return components;
    }

    public void setComponents(int components) {
        this.components = components;
    }

    public int getVulnerableComponents() {
        return vulnerableComponents;
    }

    public void setVulnerableComponents(int vulnerableComponents) {
        this.vulnerableComponents = vulnerableComponents;
    }

    public int getSuppressed() {
        return suppressed;
    }

    public void setSuppressed(int suppressed) {
        this.suppressed = suppressed;
    }

    public int getFindingsTotal() {
        return findingsTotal;
    }

    public void setFindingsTotal(int findingsTotal) {
        this.findingsTotal = findingsTotal;
    }

    public int getFindingsAudited() {
        return findingsAudited;
    }

    public void setFindingsAudited(int findingsAudited) {
        this.findingsAudited = findingsAudited;
    }

    public int getFindingsUnaudited() {
        return findingsUnaudited;
    }

    public void setFindingsUnaudited(int findingsUnaudited) {
        this.findingsUnaudited = findingsUnaudited;
    }

    public double getInheritedRiskScore() {
        return inheritedRiskScore;
    }

    public void setInheritedRiskScore(double inheritedRiskScore) {
        this.inheritedRiskScore = inheritedRiskScore;
    }

    public int getPolicyViolationsFail() {
        return policyViolationsFail;
    }

    public void setPolicyViolationsFail(int policyViolationsFail) {
        this.policyViolationsFail = policyViolationsFail;
    }

    public int getPolicyViolationsWarn() {
        return policyViolationsWarn;
    }

    public void setPolicyViolationsWarn(int policyViolationsWarn) {
        this.policyViolationsWarn = policyViolationsWarn;
    }

    public int getPolicyViolationsInfo() {
        return policyViolationsInfo;
    }

    public void setPolicyViolationsInfo(int policyViolationsInfo) {
        this.policyViolationsInfo = policyViolationsInfo;
    }

    public int getPolicyViolationsTotal() {
        return policyViolationsTotal;
    }

    public void setPolicyViolationsTotal(int policyViolationsTotal) {
        this.policyViolationsTotal = policyViolationsTotal;
    }

    public int getPolicyViolationsAudited() {
        return policyViolationsAudited;
    }

    public void setPolicyViolationsAudited(int policyViolationsAudited) {
        this.policyViolationsAudited = policyViolationsAudited;
    }

    public int getPolicyViolationsUnaudited() {
        return policyViolationsUnaudited;
    }

    public void setPolicyViolationsUnaudited(int policyViolationsUnaudited) {
        this.policyViolationsUnaudited = policyViolationsUnaudited;
    }

    public int getPolicyViolationsSecurityTotal() {
        return policyViolationsSecurityTotal;
    }

    public void setPolicyViolationsSecurityTotal(int policyViolationsSecurityTotal) {
        this.policyViolationsSecurityTotal = policyViolationsSecurityTotal;
    }

    public int getPolicyViolationsSecurityAudited() {
        return policyViolationsSecurityAudited;
    }

    public void setPolicyViolationsSecurityAudited(int policyViolationsSecurityAudited) {
        this.policyViolationsSecurityAudited = policyViolationsSecurityAudited;
    }

    public int getPolicyViolationsSecurityUnaudited() {
        return policyViolationsSecurityUnaudited;
    }

    public void setPolicyViolationsSecurityUnaudited(int policyViolationsSecurityUnaudited) {
        this.policyViolationsSecurityUnaudited = policyViolationsSecurityUnaudited;
    }

    public int getPolicyViolationsLicenseTotal() {
        return policyViolationsLicenseTotal;
    }

    public void setPolicyViolationsLicenseTotal(int policyViolationsLicenseTotal) {
        this.policyViolationsLicenseTotal = policyViolationsLicenseTotal;
    }

    public int getPolicyViolationsLicenseAudited() {
        return policyViolationsLicenseAudited;
    }

    public void setPolicyViolationsLicenseAudited(int policyViolationsLicenseAudited) {
        this.policyViolationsLicenseAudited = policyViolationsLicenseAudited;
    }

    public int getPolicyViolationsLicenseUnaudited() {
        return policyViolationsLicenseUnaudited;
    }

    public void setPolicyViolationsLicenseUnaudited(int policyViolationsLicenseUnaudited) {
        this.policyViolationsLicenseUnaudited = policyViolationsLicenseUnaudited;
    }

    public int getPolicyViolationsOperationalTotal() {
        return policyViolationsOperationalTotal;
    }

    public void setPolicyViolationsOperationalTotal(int policyViolationsOperationalTotal) {
        this.policyViolationsOperationalTotal = policyViolationsOperationalTotal;
    }

    public int getPolicyViolationsOperationalAudited() {
        return policyViolationsOperationalAudited;
    }

    public void setPolicyViolationsOperationalAudited(int policyViolationsOperationalAudited) {
        this.policyViolationsOperationalAudited = policyViolationsOperationalAudited;
    }

    public int getPolicyViolationsOperationalUnaudited() {
        return policyViolationsOperationalUnaudited;
    }

    public void setPolicyViolationsOperationalUnaudited(int policyViolationsOperationalUnaudited) {
        this.policyViolationsOperationalUnaudited = policyViolationsOperationalUnaudited;
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
