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
package org.dependencytrack.parser.github.graphql.model;

import org.apache.commons.lang3.tuple.Pair;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;

public class GitHubSecurityAdvisory {

    private int databaseId;
    private String description;
    private String ghsaId;
    private String id;
    private List<Pair<String, String>> identifiers;
    private String notificationsPermalink;
    private String origin;
    private String permalink;
    private List<String> references;
    private String severity;
    private String summary;
    private ZonedDateTime publishedAt;
    private ZonedDateTime updatedAt;
    private ZonedDateTime withdrawnAt;
    private List<GitHubVulnerability> vulnerabilities;
    private double cvssScore;
    private String cvssVector;
    private List<String> cwes;

    public int getDatabaseId() {
        return databaseId;
    }

    public void setDatabaseId(int databaseId) {
        this.databaseId = databaseId;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getGhsaId() {
        return ghsaId;
    }

    public void setGhsaId(String ghsaId) {
        this.ghsaId = ghsaId;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<Pair<String, String>> getIdentifiers() {
        return identifiers;
    }

    public void addIdentifier(Pair<String, String> identifier) {
        if (this.identifiers == null) {
            this.identifiers = new ArrayList<>();
        }
        this.identifiers.add(identifier);
    }

    public void setIdentifiers(List<Pair<String, String>> identifiers) {
        this.identifiers = identifiers;
    }

    public String getNotificationsPermalink() {
        return notificationsPermalink;
    }

    public void setNotificationsPermalink(String notificationsPermalink) {
        this.notificationsPermalink = notificationsPermalink;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public String getPermalink() {
        return permalink;
    }

    public void setPermalink(String permalink) {
        this.permalink = permalink;
    }

    public List<String> getReferences() {
        return references;
    }

    public void addReference(String reference) {
        if (this.references == null) {
            this.references = new ArrayList<>();
        }
        this.references.add(reference);
    }

    public void setReferences(List<String> references) {
        this.references = references;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public ZonedDateTime getPublishedAt() {
        return publishedAt;
    }

    public void setPublishedAt(ZonedDateTime publishedAt) {
        this.publishedAt = publishedAt;
    }

    public ZonedDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(ZonedDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public ZonedDateTime getWithdrawnAt() {
        return withdrawnAt;
    }

    public void setWithdrawnAt(ZonedDateTime withdrawnAt) {
        this.withdrawnAt = withdrawnAt;
    }

    public List<GitHubVulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<GitHubVulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public double getCvssScore() {
        return cvssScore;
    }

    public void setCvssScore(double cvssScore) {
        this.cvssScore = cvssScore;
    }

    public String getCvssVector() {
        return cvssVector;
    }

    public void setCvssVector(String cvssVector) {
        this.cvssVector = cvssVector;
    }

    public List<String> getCwes() {
        return cwes;
    }

    public void addCwe(String cwe) {
        if (cwes == null) {
            cwes = new ArrayList<>();
        }
        cwes.add(cwe);
    }

    public void setCwes(List<String> cwes) {
        this.cwes = cwes;
    }
}
