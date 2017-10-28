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
package org.owasp.dependencytrack.parser.dependencycheck.model;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
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
    private Vulnerabilities vulnerabilities;

    public boolean isVirtual() {
        return isVirtual;
    }

    @XmlAttribute(name = "isVirtual")
    public void setVirtual(boolean virtual) {
        isVirtual = virtual;
    }

    public String getFileName() {
        return fileName;
    }

    @XmlElement(name = "fileName")
    public void setFileName(String fileName) {
        this.fileName = normalize(fileName);
    }

    public String getFilePath() {
        return filePath;
    }

    @XmlElement(name = "filePath")
    public void setFilePath(String filePath) {
        this.filePath = normalize(filePath);
    }

    public String getMd5() {
        return md5;
    }

    @XmlElement(name = "md5")
    public void setMd5(String md5) {
        this.md5 = normalize(md5);
    }

    public String getSha1() {
        return sha1;
    }

    @XmlElement(name = "sha1")
    public void setSha1(String sha1) {
        this.sha1 = normalize(sha1);
    }

    public String getDescription() {
        return description;
    }

    @XmlElement(name = "description")
    public void setDescription(String description) {
        this.description = normalize(description);
    }

    public String getLicense() {
        return license;
    }

    @XmlElement(name = "license")
    public void setLicense(String license) {
        this.license = normalize(license);
    }

    public List<Evidence> getEvidenceCollected() {
        return evidenceCollected;
    }

    @XmlElementWrapper(name = "evidenceCollected")
    @XmlElement(name = "evidence")
    public void setEvidenceCollected(List<Evidence> evidenceCollected) {
        this.evidenceCollected = evidenceCollected;
    }

    public Identifiers getIdentifiers() {
        return identifiers;
    }

    @XmlElement(name = "identifiers")
    public void setIdentifiers(Identifiers identifiers) {
        this.identifiers = identifiers;
    }

    public Vulnerabilities getVulnerabilities() {
        return vulnerabilities;
    }

    @XmlElement(name = "vulnerabilities")
    public void setVulnerabilities(Vulnerabilities vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
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

        @XmlElement(name = "identifier")
        public void setIdentifiers(List<Identifier> identifiers) {
            this.identifiers = identifiers;
        }

        public List<Identifier> getSuppressedIdentifiers() {
            return suppressedIdentifiers;
        }

        @XmlElement(name = "suppressedIdentifier")
        public void setSuppressedIdentifiers(List<Identifier> suppressedIdentifiers) {
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
        public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
            this.vulnerabilities = vulnerabilities;
        }

        public List<Vulnerability> getSuppressedVulnerabilities() {
            return suppressedVulnerabilities;
        }

        @XmlElement(name = "suppressedVulnerability")
        public void setSuppressedVulnerabilities(List<Vulnerability> suppressedVulnerabilities) {
            this.suppressedVulnerabilities = suppressedVulnerabilities;
        }
    }
}
