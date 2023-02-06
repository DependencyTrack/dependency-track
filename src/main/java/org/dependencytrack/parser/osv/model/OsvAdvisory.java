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
package org.dependencytrack.parser.osv.model;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;

public class OsvAdvisory {

    private String id;

    private String details;

    private String summary;

    private String severity;

    private List<String> aliases;

    private ZonedDateTime modified;

    private ZonedDateTime published;

    private ZonedDateTime withdrawn;

    private List<String> cweIds;

    private List<String> references;

    private List<String> credits;

    private String schema_version;

    private List<OsvAffectedPackage> affectedPackages;

    private String cvssV2Vector;

    private String cvssV3Vector;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<String> getCweIds() {
        return cweIds;
    }

    public void addCweId(String cweId) {
        if (cweIds == null) {
            cweIds = new ArrayList<>();
        }
        cweIds.add(cweId);
    }

    public void setCweIds(List<String> cweIds) {
        this.cweIds = cweIds;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public List<String> getAliases() {
        return aliases;
    }

    public void addAlias(String alias) {
        if (aliases == null) {
            aliases = new ArrayList<>();
        }
        aliases.add(alias);
    }

    public void setAliases(List<String> aliases) {
        this.aliases = aliases;
    }

    public ZonedDateTime getModified() {
        return modified;
    }

    public void setModified(ZonedDateTime modified) {
        this.modified = modified;
    }

    public ZonedDateTime getPublished() {
        return published;
    }

    public void setPublished(ZonedDateTime published) {
        this.published = published;
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

    public String getSchema_version() {
        return schema_version;
    }

    public void setSchema_version(String schema_version) {
        this.schema_version = schema_version;
    }

    public List<OsvAffectedPackage> getAffectedPackages() {
        return affectedPackages;
    }

    public void setAffectedPackages(List<OsvAffectedPackage> affectedPackages) {
        this.affectedPackages = affectedPackages;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public ZonedDateTime getWithdrawn() {
        return withdrawn;
    }

    public void setWithdrawn(ZonedDateTime withdrawn) {
        this.withdrawn = withdrawn;
    }

    public String getCvssV2Vector() {
        return cvssV2Vector;
    }

    public void setCvssV2Vector(String cvssV2Vector) {
        this.cvssV2Vector = cvssV2Vector;
    }

    public String getCvssV3Vector() {
        return cvssV3Vector;
    }

    public void setCvssV3Vector(String cvssV3Vector) {
        this.cvssV3Vector = cvssV3Vector;
    }

    public List<String> getCredits() {
        return credits;
    }

    public void addCredit(String credit) {
        if (this.credits == null) {
            this.credits = new ArrayList<>();
        }
        this.credits.add(credit);
    }

    public void setCredits(List<String> credits) {
        this.credits = credits;
    }

}