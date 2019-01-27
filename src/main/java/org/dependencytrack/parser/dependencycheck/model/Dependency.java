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
package org.dependencytrack.parser.dependencycheck.model;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;

/**
 * Defines the dependency element in a Dependency-Check report.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@XmlRootElement(name = "dependency")
public class Dependency extends BaseObject {

    private boolean isVirtual;
    private String fileName;
    private String filePath;
    private String md5;
    private String sha1;
    private String description;
    private String license;
    private List<Evidence> evidenceCollected;
    private Identifiers identifiers;
    private Identifier identifier; // Related dependencies only have a single identifier element
    private Vulnerabilities vulnerabilities;
    private List<Dependency> relatedDependencies;

    public boolean isVirtual() {
        return isVirtual;
    }

    @XmlAttribute(name = "isVirtual")
    public void setVirtual(final boolean virtual) {
        isVirtual = virtual;
    }

    public String getFileName() {
        return fileName;
    }

    @XmlElement(name = "fileName")
    public void setFileName(final String fileName) {
        this.fileName = normalize(fileName);
    }

    public String getFilePath() {
        return filePath;
    }

    @XmlElement(name = "filePath")
    public void setFilePath(final String filePath) {
        this.filePath = normalize(filePath);
    }

    public String getMd5() {
        return md5;
    }

    @XmlElement(name = "md5")
    public void setMd5(final String md5) {
        this.md5 = normalize(md5);
    }

    public String getSha1() {
        return sha1;
    }

    @XmlElement(name = "sha1")
    public void setSha1(final String sha1) {
        this.sha1 = normalize(sha1);
    }

    public String getDescription() {
        return description;
    }

    @XmlElement(name = "description")
    public void setDescription(final String description) {
        this.description = normalize(description);
    }

    public String getLicense() {
        return license;
    }

    @XmlElement(name = "license")
    public void setLicense(final String license) {
        this.license = normalize(license);
    }

    public List<Evidence> getEvidenceCollected() {
        return evidenceCollected;
    }

    @XmlElementWrapper(name = "evidenceCollected")
    @XmlElement(name = "evidence")
    public void setEvidenceCollected(final List<Evidence> evidenceCollected) {
        this.evidenceCollected = evidenceCollected;
    }

    public Identifiers getIdentifiers() {
        return identifiers;
    }

    @XmlElement(name = "identifiers")
    public void setIdentifiers(final Identifiers identifiers) {
        this.identifiers = identifiers;
    }

    public Identifier getIdentifier() {
        return identifier;
    }

    @XmlElement(name = "identifier")
    public void setIdentifier(final Identifier identifier) {
        if (this.identifiers == null) {
            this.identifiers = new Identifiers();
        }
        this.identifiers.addIdentifier(identifier);
        this.identifier = identifier;
    }

    public Vulnerabilities getVulnerabilities() {
        return vulnerabilities;
    }

    @XmlElement(name = "vulnerabilities")
    public void setVulnerabilities(final Vulnerabilities vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public List<Dependency> getRelatedDependencies() {
        return relatedDependencies;
    }

    @XmlElementWrapper(name = "relatedDependencies")
    @XmlElement(name = "relatedDependency")
    public void setRelatedDependencies(final List<Dependency> dependencies) {
        this.relatedDependencies = dependencies;
    }

    /**
     * Defines a list of identifier elements for the dependency.
     */
    @XmlRootElement(name = "identifiers")
    public static class Identifiers {

        private List<Identifier> identifiers;
        private List<Identifier> suppressedIdentifiers;

        public List<Identifier> getIdentifiers() {
            return identifiers;
        }

        public void addIdentifier(final Identifier identifier) {
            if (identifiers == null) {
                identifiers = new ArrayList<>();
            }
            identifiers.add(identifier);
        }

        @XmlElement(name = "identifier")
        public void setIdentifiers(final List<Identifier> identifiers) {
            this.identifiers = identifiers;
        }

        public List<Identifier> getSuppressedIdentifiers() {
            return suppressedIdentifiers;
        }

        @XmlElement(name = "suppressedIdentifier")
        public void setSuppressedIdentifiers(final List<Identifier> suppressedIdentifiers) {
            this.suppressedIdentifiers = suppressedIdentifiers;
        }
    }

    /**
     * Defines a list of vulnerability elements for the dependency.
     */
    @XmlRootElement(name = "vulnerabilities")
    public static class Vulnerabilities {

        private List<Vulnerability> vulnerabilities;
        private List<Vulnerability> suppressedVulnerabilities;

        public List<Vulnerability> getVulnerabilities() {
            return vulnerabilities;
        }

        @XmlElement(name = "vulnerability")
        public void setVulnerabilities(final List<Vulnerability> vulnerabilities) {
            this.vulnerabilities = vulnerabilities;
        }

        public List<Vulnerability> getSuppressedVulnerabilities() {
            return suppressedVulnerabilities;
        }

        @XmlElement(name = "suppressedVulnerability")
        public void setSuppressedVulnerabilities(final List<Vulnerability> suppressedVulnerabilities) {
            this.suppressedVulnerabilities = suppressedVulnerabilities;
        }
    }
}
