/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.parser.npm.model;

/**
 * The response from NPM Audit API will respond with 0 or more advisories. This
 * class defines the Advisory objects returned. This class is adapted from the
 * original NPM version of the same class.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
public class Advisory {

    /**
     * The unique ID of the advisory as issued by Node Security Platform.
     */
    private int id;

    /**
     * The timestamp of which the advisory was created.
     */
    private String created;

    /**
     * The timestamp of the last update to the advisory.
     */
    private String updated;

    /**
     * The title/name of the advisory.
     */
    private String title;

    /**
     * A detailed description of the advisory.
     */
    private String overview;

    /**
     * Recommendations for mitigation. Typically involves updating to a newer
     * release.
     */
    private String recommendation;

    /**
     * The name of the individual or organization that found the issue.
     */
    private String foundBy;

    /**
     * The name of the individual or organization that reported the issue.
     */
    private String reportedBy;

    /**
     * The name of the Node module the advisory is for.
     */
    private String moduleName;

    /**
     * The version of the Node module.
     */
    private String version;

    /**
     * The optional CVE(s) associated with this advisory.
     */
    private String[] cves;

    /**
     * A string representation of the versions containing the vulnerability.
     */
    private String vulnerableVersions;

    /**
     * A string representation of the versions that have been patched.
     */
    private String patchedVersions;

    /**
     * The references names in the advisory. This field contains MarkDown (including \n, *, and other characters)
     */
    private String references;

    /**
     * The access of the advisory.
     */
    private String access;

    /**
     * The severity of the advisory.
     */
    private String severity;

    /**
     * The CWE of the advisory.
     */
    private String cwe;


    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getCreated() {
        return created;
    }

    public void setCreated(String created) {
        this.created = created;
    }

    public String getUpdated() {
        return updated;
    }

    public void setUpdated(String updated) {
        this.updated = updated;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getOverview() {
        return overview;
    }

    public void setOverview(String overview) {
        this.overview = overview;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public String getFoundBy() {
        return foundBy;
    }

    public void setFoundBy(String foundBy) {
        this.foundBy = foundBy;
    }

    public String getReportedBy() {
        return reportedBy;
    }

    public void setReportedBy(String reportedBy) {
        this.reportedBy = reportedBy;
    }

    public String getModuleName() {
        return moduleName;
    }

    public void setModuleName(String moduleName) {
        this.moduleName = moduleName;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String[] getCves() {
        return cves;
    }

    public void setCves(String[] cves) {
        this.cves = cves;
    }

    public String getVulnerableVersions() {
        return vulnerableVersions;
    }

    public void setVulnerableVersions(String vulnerableVersions) {
        this.vulnerableVersions = vulnerableVersions;
    }

    public String getPatchedVersions() {
        return patchedVersions;
    }

    public void setPatchedVersions(String patchedVersions) {
        this.patchedVersions = patchedVersions;
    }

    public String getReferences() {
        return references;
    }

    public void setReferences(String references) {
        this.references = references;
    }

    public String getAccess() {
        return access;
    }

    public void setAccess(String access) {
        this.access = access;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getCwe() {
        return cwe;
    }

    public void setCwe(String cwe) {
        this.cwe = cwe;
    }
}
