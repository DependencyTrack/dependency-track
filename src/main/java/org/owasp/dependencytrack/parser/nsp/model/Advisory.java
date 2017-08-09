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
package org.owasp.dependencytrack.parser.nsp.model;

import java.util.Arrays;

/**
 * The response from NSP check API will respond with 0 or more advisories. This
 * class defines the Advisory objects returned.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class Advisory {

    /**
     * The unique ID of the advisory as issued by Node Security Platform.
     */
    private int id;

    /**
     * The timestamp of the last update to the advisory.
     */
    private String updatedAt;

    /**
     * The timestamp of which the advisory was created.
     */
    private String createdAt;

    /**
     * The timestamp of when the advisory was published.
     */
    private String publishDate;

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
     * The CVSS vector used to calculate the score.
     */
    private String cvssVector;

    /**
     * The CVSS score.
     */
    private double cvssScore;

    /**
     * The name of the Node module the advisory is for.
     */
    private String moduleName;

    /**
     * The slug of the Node module the advisory is for.
     */
    private String slug;

    /**
     * The legacy slug of the Node module the advisory is for.
     */
    private String legacySlug;

    /**
     * A string representation of the versions containing the vulnerability.
     */
    private String vulnerableVersions;

    /**
     * A string representation of the versions that have been patched.
     */
    private String patchedVersions;

    /**
     * The title/name of the advisory.
     */
    private String title;

    /**
     * The optional CVE(s) associated with this advisory.
     */
    private String[] cves;

    /**
     * The references names in the advisory. This field contains MarkDown (including \n, *, and other characters)
     */
    private String references;

    /**
     * The name of the author(s)
     */
    private String author;

    /**
     * Returns the unique ID of the advisory as issued by Node Security
     * Platform.
     *
     * @return a unique ID
     */
    public int getId() {
        return id;
    }

    /**
     * Sets the unique ID of the advisory as issued by Node Security Platform.
     *
     * @param id a unique ID
     */
    public void setId(int id) {
        this.id = id;
    }

    /**
     * Returns the timestamp of the last update to the advisory.
     *
     * @return a timestamp
     */
    public String getUpdatedAt() {
        return updatedAt;
    }

    /**
     * Sets the timestamp of the last update to the advisory.
     *
     * @param updatedAt a timestamp
     */
    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * Returns the timestamp of which the advisory was created.
     *
     * @return a timestamp
     */
    public String getCreatedAt() {
        return createdAt;
    }

    /**
     * Sets the timestamp of which the advisory was created.
     *
     * @param createdAt a timestamp
     */
    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * Returns the timestamp of when the advisory was published.
     *
     * @return a timestamp
     */
    public String getPublishDate() {
        return publishDate;
    }

    /**
     * Sets the timestamp of when the advisory was published.
     *
     * @param publishDate a timestamp
     */
    public void setPublishDate(String publishDate) {
        this.publishDate = publishDate;
    }

    /**
     * Returns a detailed description of the advisory.
     *
     * @return the overview
     */
    public String getOverview() {
        return overview;
    }

    /**
     * Sets the detailed description of the advisory.
     *
     * @param overview the overview
     */
    public void setOverview(String overview) {
        this.overview = overview;
    }

    /**
     * Returns recommendations for mitigation. Typically involves updating to a
     * newer release.
     *
     * @return recommendations
     */
    public String getRecommendation() {
        return recommendation;
    }

    /**
     * Sets recommendations for mitigation. Typically involves updating to a
     * newer release.
     *
     * @param recommendation recommendations
     */
    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    /**
     * Returns the CVSS vector used to calculate the score.
     *
     * @return the CVSS vector
     */
    public String getCvssVector() {
        return cvssVector;
    }

    /**
     * Sets the CVSS vector used to calculate the score.
     *
     * @param cvssVector the CVSS vector
     */
    public void setCvssVector(String cvssVector) {
        this.cvssVector = cvssVector;
    }

    /**
     * Returns the CVSS score.
     *
     * @return the CVSS score
     */
    public double getCvssScore() {
        return cvssScore;
    }

    /**
     * Sets the CVSS score.
     *
     * @param cvssScore the CVSS score
     */
    public void setCvssScore(double cvssScore) {
        this.cvssScore = cvssScore;
    }

    /**
     * Returns the name of the Node module the advisory is for.
     *
     * @return the name of the module
     */
    public String getModuleName() {
        return moduleName;
    }

    /**
     * Sets the name of the Node module the advisory is for.
     *
     * @param moduleName the name of the4 module
     */
    public void setModuleName(String moduleName) {
        this.moduleName = moduleName;
    }

    /**
     * Returns the slug of the Node module the advisory is for.
     *
     * @return the module version
     */
    public String getSlug() {
        return slug;
    }

    /**
     * Sets the slug of the Node module the advisory is for.
     *
     * @param slug the module version
     */
    public void setSlug(String slug) {
        this.slug = slug;
    }

    /**
     * Returns the legacy slug of the Node module the advisory is for.
     *
     * @return the module version
     */
    public String getLegacySlug() {
        return legacySlug;
    }

    /**
     * Sets the legacy slug of the Node module the advisory is for.
     *
     * @param legacySlug the module version
     */
    public void setLegacySlug(String legacySlug) {
        this.legacySlug = legacySlug;
    }

    /**
     * Returns a string representation of the versions containing the
     * vulnerability.
     *
     * @return the affected versions
     */
    public String getVulnerableVersions() {
        return vulnerableVersions;
    }

    /**
     * Sets the string representation of the versions containing the
     * vulnerability.
     *
     * @param vulnerableVersions the affected versions
     */
    public void setVulnerableVersions(String vulnerableVersions) {
        this.vulnerableVersions = vulnerableVersions;
    }

    /**
     * Returns a string representation of the versions that have been patched.
     *
     * @return the patched versions
     */
    public String getPatchedVersions() {
        return patchedVersions;
    }

    /**
     * Sets the string representation of the versions that have been patched.
     *
     * @param patchedVersions the patched versions
     */
    public void setPatchedVersions(String patchedVersions) {
        this.patchedVersions = patchedVersions;
    }

    /**
     * Returns the title/name of the advisory.
     *
     * @return the title/name of the advisory
     */
    public String getTitle() {
        return title;
    }

    /**
     * Sets the title/name of the advisory.
     *
     * @param title the title/name of the advisory
     */
    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * Returns the CVE(s) associated with this advisory.
     *
     * @return the CVE(s) associated with this advisory
     */
    public String[] getCVEs() {
        if (cves == null) {
            return null;
        }
        return Arrays.copyOf(cves, cves.length);
    }

    /**
     * Sets the CVE(s) associated with this advisory.
     *
     * @param cves the CVE(s) associated with this advisory
     */
    public void setCVEs(String[] cves) {
        if (cves == null) {
            this.cves = null;
        } else {
            this.cves = Arrays.copyOf(cves, cves.length);
        }
    }

    /**
     * Returns the references named in the advisory.
     *
     * @return the advisory references (in MarkDown format)
     */
    public String getReferences() {
        return references;
    }

    /**
     * Sets the references named in the advisory.
     *
     * @param references the advisory references (in MarkDown format)
     */
    public void setReferences(String references) {
        this.references = references;
    }

    /**
     * Returns the author(s) of the advisory.
     *
     * @return the author(s) of the advisory
     */
    public String getAuthor() {
        return author;
    }

    /**
     * Sets the author(s) of the advisory.
     *
     * @param author the author(s) of the advisory
     */
    public void setAuthor(String author) {
        this.author = author;
    }
}
