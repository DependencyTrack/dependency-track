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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.model.sqlmapping;

import org.apache.commons.lang3.SerializationUtils;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Scope;
import org.dependencytrack.persistence.converter.OrganizationalContactsJsonConverter;

import java.util.Date;
import java.util.UUID;

public class ComponentProjection {

    public long id;

    public String uuid;

    public String authors;

    public String group;

    public String name;

    public String text;

    public String publisher;

    public String version;

    public String classifier;

    public String copyright;

    public String description;

    public String extension;

    public String filename;

    public byte[] externalReferences;

    public String directDependencies;

    public String cpe;

    public String purl;

    public String purlCoordinates;

    public String scope;

    public String swidTagId;

    public Boolean internal;

    public Double lastInheritedRiskScore;

    public String md5;

    public String sha1;

    public String sha256;

    public String sha384;

    public String sha512;

    public String sha3_256;

    public String sha3_384;

    public String sha3_512;

    public String blake2b_256;

    public String blake2b_384;

    public String blake2b_512;

    public String blake3;

    public String licenseUrl;

    public String componentLicenseName;

    public String licenseExpression;

    public Long projectId;

    public String projectUuid;

    public String projectGroup;

    public String projectName;

    public String projectVersion;

    public String projectClassifier;

    public Date projectInactiveSince;

    public String projectAuthors;

    public String projectCpe;

    public String projectDescription;

    public String projectPurl;

    public String projectSwidTagId;

    public Date lastBomImport;

    public String lastBomImportFormat;

    public Double projectLastInheritedRiskScore;

    public String projectDirectDependencies;

    public byte[] projectExternalReferences;

    public String projectPublisher;

    public String licenseUuid;

    public String licenseId;
    public String licenseName;

    public Boolean isOsiApproved;

    public Boolean isFsfLibre;

    public Boolean isCustomLicense;

    public long occurrenceCount;
    public Long totalCount;

    public static Component mapToComponent(ComponentProjection result) {
        Component componentPersistent = new Component();
        if (result.authors != null) {
            final var converter = new OrganizationalContactsJsonConverter();
            componentPersistent.setAuthors(converter.convertToAttribute(result.authors));
        }
        componentPersistent.setBlake2b_256(result.blake2b_256);
        componentPersistent.setBlake2b_384(result.blake2b_384);
        componentPersistent.setBlake2b_512(result.blake2b_512);
        componentPersistent.setBlake3(result.blake3);
        if (result.classifier != null) {
            componentPersistent.setClassifier(Classifier.valueOf(result.classifier));
        }
        componentPersistent.setCopyright(result.copyright);
        componentPersistent.setCpe(result.cpe);
        componentPersistent.setDescription(result.description);
        componentPersistent.setDirectDependencies(result.directDependencies);
        componentPersistent.setExtension(result.extension);
        componentPersistent.setGroup(result.group);
        componentPersistent.setId(result.id);
        if (result.internal != null) {
            componentPersistent.setInternal(result.internal);
        }
        componentPersistent.setScope(result.scope != null ? Scope.valueOf(result.scope) : null);
        componentPersistent.setNotes(result.text);
        componentPersistent.setSwidTagId(result.swidTagId);
        componentPersistent.setLastInheritedRiskScore(result.lastInheritedRiskScore);
        componentPersistent.setLicense(result.componentLicenseName);
        componentPersistent.setLicenseUrl(result.licenseUrl);
        componentPersistent.setLicenseExpression(result.licenseExpression);
        componentPersistent.setName(result.name);
        if (result.uuid != null) {
            componentPersistent.setUuid(UUID.fromString(result.uuid));
        }
        if (result.externalReferences != null) {
            componentPersistent.setExternalReferences(SerializationUtils.deserialize(result.externalReferences));
        }
        componentPersistent.setOccurrenceCount(result.occurrenceCount);
        componentPersistent.setPurl(result.purl);
        componentPersistent.setPurlCoordinates(result.purlCoordinates);
        componentPersistent.setVersion(result.version);
        componentPersistent.setMd5(result.md5);
        componentPersistent.setSha1(result.sha1);
        componentPersistent.setSha256(result.sha256);
        componentPersistent.setSha384(result.sha384);
        componentPersistent.setSha512(result.sha512);
        componentPersistent.setSha3_256(result.sha3_256);
        componentPersistent.setSha3_384(result.sha3_384);
        componentPersistent.setSha3_512(result.sha3_512);

        var project = new Project();
        if (result.projectId != null) {
            project.setId(result.projectId);
        }
        if (result.projectAuthors != null) {
            final var converter = new OrganizationalContactsJsonConverter();
            project.setAuthors(converter.convertToAttribute(result.projectAuthors));
        }
        if (result.projectInactiveSince != null) {
            project.setInactiveSince(result.projectInactiveSince);
        }
        project.setDescription(result.projectDescription);
        project.setCpe(result.projectCpe);
        project.setPurl(result.projectPurl);
        project.setSwidTagId(result.projectSwidTagId);
        project.setPublisher(result.projectPublisher);
        if (result.projectExternalReferences != null) {
            project.setExternalReferences(SerializationUtils.deserialize(result.projectExternalReferences));
        }
        project.setLastInheritedRiskScore(result.projectLastInheritedRiskScore);
        if (result.projectClassifier != null) {
            project.setClassifier(Classifier.valueOf(result.projectClassifier));
        }
        project.setDirectDependencies(result.projectDirectDependencies);
        project.setLastBomImport(result.lastBomImport);
        project.setLastBomImportFormat(result.lastBomImportFormat);
        project.setGroup(result.projectGroup);
        project.setName(result.projectName);
        if (result.projectUuid != null) {
            project.setUuid(UUID.fromString(result.projectUuid));
        }
        project.setVersion(result.projectVersion);
        componentPersistent.setProject(project);

        if (result.licenseUuid != null) {
            final var license = new License();
            license.setUuid(UUID.fromString(result.licenseUuid));
            license.setLicenseId(result.licenseId);
            license.setName(result.licenseName);
            if (result.isCustomLicense != null) {
                license.setCustomLicense(result.isCustomLicense);
            }
            if (result.isFsfLibre != null) {
                license.setFsfLibre(result.isFsfLibre);
            }
            if (result.isOsiApproved != null) {
                license.setOsiApproved(result.isOsiApproved);
            }
            componentPersistent.setResolvedLicense(license);
        }

        return componentPersistent;
    }
}
