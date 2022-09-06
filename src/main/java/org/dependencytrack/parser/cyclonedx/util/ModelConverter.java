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
package org.dependencytrack.parser.cyclonedx.util;

import alpine.common.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Swid;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.DataClassification;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.License;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.cyclonedx.CycloneDXExporter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.InternalComponentIdentificationUtil;
import org.dependencytrack.util.PurlUtil;
import org.json.JSONArray;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class ModelConverter {

    private static final Logger LOGGER = Logger.getLogger(ModelConverter.class);

    /**
     * Private Constructor.
     */
    private ModelConverter() { }

    /**
     * Converts a parsed Bom to a native list of Dependency-Track component object
     * @param bom the Bom to convert
     * @return a List of Component object
     */
    public static List<Component> convertComponents(final QueryManager qm, final Bom bom, final Project project) {
        final List<Component> components = new ArrayList<>();
        if (bom.getComponents() != null) {
            for (int i = 0; i < bom.getComponents().size(); i++) {
                final org.cyclonedx.model.Component cycloneDxComponent = bom.getComponents().get(i);
                if (cycloneDxComponent != null) {
                    components.add(convert(qm, cycloneDxComponent, project));
                }
            }
        }
        return components;
    }

    @SuppressWarnings("deprecation")
    public static Component convert(final QueryManager qm, final org.cyclonedx.model.Component cycloneDxComponent, final Project project) {
        Component component = qm.matchSingleIdentity(project, new ComponentIdentity(cycloneDxComponent));
        if (component == null) {
            component = new Component();
            component.setProject(project);
        }
        component.setAuthor(StringUtils.trimToNull(cycloneDxComponent.getAuthor()));
        component.setBomRef(StringUtils.trimToNull(cycloneDxComponent.getBomRef()));
        component.setPublisher(StringUtils.trimToNull(cycloneDxComponent.getPublisher()));
        component.setGroup(StringUtils.trimToNull(cycloneDxComponent.getGroup()));
        component.setName(StringUtils.trimToNull(cycloneDxComponent.getName()));
        component.setVersion(StringUtils.trimToNull(cycloneDxComponent.getVersion()));
        component.setDescription(StringUtils.trimToNull(cycloneDxComponent.getDescription()));
        component.setCopyright(StringUtils.trimToNull(cycloneDxComponent.getCopyright()));
        component.setCpe(StringUtils.trimToNull(cycloneDxComponent.getCpe()));

        if (cycloneDxComponent.getSwid() != null) {
            component.setSwidTagId(StringUtils.trimToNull(cycloneDxComponent.getSwid().getTagId()));
        }

        if (StringUtils.isNotBlank(cycloneDxComponent.getPurl())) {
            try {
                final PackageURL purl = new PackageURL(StringUtils.trimToNull(cycloneDxComponent.getPurl()));
                component.setPurl(purl);
                component.setPurlCoordinates(PurlUtil.purlCoordinatesOnly(purl));
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Unable to parse PackageURL: " + cycloneDxComponent.getPurl());
            }
        }

        component.setInternal(InternalComponentIdentificationUtil.isInternalComponent(component, qm));

        if (cycloneDxComponent.getType() != null) {
            component.setClassifier(Classifier.valueOf(cycloneDxComponent.getType().name()));
        } else {
            component.setClassifier(Classifier.LIBRARY);
        }

        if (cycloneDxComponent.getHashes() != null && !cycloneDxComponent.getHashes().isEmpty()) {
            for (final Hash hash : cycloneDxComponent.getHashes()) {
                if (hash != null) {
                    if (Hash.Algorithm.MD5.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                        component.setMd5(StringUtils.trimToNull(hash.getValue()));
                    } else if (Hash.Algorithm.SHA1.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                        component.setSha1(StringUtils.trimToNull(hash.getValue()));
                    } else if (Hash.Algorithm.SHA_256.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                        component.setSha256(StringUtils.trimToNull(hash.getValue()));
                    } else if (Hash.Algorithm.SHA_512.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                        component.setSha512(StringUtils.trimToNull(hash.getValue()));
                    } else if (Hash.Algorithm.SHA3_256.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                        component.setSha3_256(StringUtils.trimToNull(hash.getValue()));
                    } else if (Hash.Algorithm.SHA3_512.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                        component.setSha3_512(StringUtils.trimToNull(hash.getValue()));
                    }
                }
            }
        }

        final LicenseChoice licenseChoice = cycloneDxComponent.getLicenseChoice();
        if (licenseChoice != null && licenseChoice.getLicenses() != null && !licenseChoice.getLicenses().isEmpty()) {
            for (final org.cyclonedx.model.License cycloneLicense : licenseChoice.getLicenses()) {
                if (cycloneLicense != null) {
                    if (StringUtils.isNotBlank(cycloneLicense.getId())) {
                        final License license = qm.getLicense(StringUtils.trimToNull(cycloneLicense.getId()));
                        if (license != null) {
                            component.setResolvedLicense(license);
                        }
                    }
                    component.setLicense(StringUtils.trimToNull(cycloneLicense.getName()));
                }
            }
        }

        if (cycloneDxComponent.getExternalReferences() != null && cycloneDxComponent.getExternalReferences().size() > 0) {
            List<ExternalReference> references = new ArrayList<>();
            for (org.cyclonedx.model.ExternalReference cycloneDxRef: cycloneDxComponent.getExternalReferences()) {
                ExternalReference ref = new ExternalReference();
                ref.setType(cycloneDxRef.getType());
                ref.setUrl(cycloneDxRef.getUrl());
                ref.setComment(cycloneDxRef.getComment());
                references.add(ref);
            }
            component.setExternalReferences(references);
        } else {
            component.setExternalReferences(null);
        }

        if (cycloneDxComponent.getComponents() != null && !cycloneDxComponent.getComponents().isEmpty()) {
            final Collection<Component> components = new ArrayList<>();
            for (int i = 0; i < cycloneDxComponent.getComponents().size(); i++) {
                final org.cyclonedx.model.Component cycloneDxChildComponent = cycloneDxComponent.getComponents().get(i);
                if (cycloneDxChildComponent != null) {
                    components.add(convert(qm, cycloneDxChildComponent, project));
                }
            }
            if (CollectionUtils.isNotEmpty(components)) {
                component.setChildren(components);
            }
        }
        return component;
    }

    @SuppressWarnings("deprecation")
    public static org.cyclonedx.model.Component convert(final QueryManager qm, final Component component) {
        final org.cyclonedx.model.Component cycloneComponent = new org.cyclonedx.model.Component();
        cycloneComponent.setBomRef(component.getUuid().toString());
        cycloneComponent.setGroup(StringUtils.trimToNull(component.getGroup()));
        cycloneComponent.setName(StringUtils.trimToNull(component.getName()));
        cycloneComponent.setVersion(StringUtils.trimToNull(component.getVersion()));
        cycloneComponent.setDescription(StringUtils.trimToNull(component.getDescription()));
        cycloneComponent.setCopyright(StringUtils.trimToNull(component.getCopyright()));
        cycloneComponent.setCpe(StringUtils.trimToNull(component.getCpe()));
        cycloneComponent.setAuthor(StringUtils.trimToNull(component.getAuthor()));

        if (component.getSwidTagId() != null) {
            final Swid swid = new Swid();
            swid.setTagId(component.getSwidTagId());
            cycloneComponent.setSwid(swid);
        }

        if (component.getPurl() != null) {
            cycloneComponent.setPurl(component.getPurl().canonicalize());
        }

        if (component.getClassifier() != null) {
            cycloneComponent.setType(org.cyclonedx.model.Component.Type.valueOf(component.getClassifier().name()));
        } else {
            cycloneComponent.setType(org.cyclonedx.model.Component.Type.LIBRARY);
        }

        if (component.getMd5() != null) {
            cycloneComponent.addHash(new Hash(Hash.Algorithm.MD5, component.getMd5()));
        }
        if (component.getSha1() != null) {
            cycloneComponent.addHash(new Hash(Hash.Algorithm.SHA1, component.getSha1()));
        }
        if (component.getSha256() != null) {
            cycloneComponent.addHash(new Hash(Hash.Algorithm.SHA_256, component.getSha256()));
        }
        if (component.getSha512() != null) {
            cycloneComponent.addHash(new Hash(Hash.Algorithm.SHA_512, component.getSha512()));
        }
        if (component.getSha3_256() != null) {
            cycloneComponent.addHash(new Hash(Hash.Algorithm.SHA3_256, component.getSha3_256()));
        }
        if (component.getSha3_512() != null) {
            cycloneComponent.addHash(new Hash(Hash.Algorithm.SHA3_512, component.getSha3_512()));
        }

        if (component.getResolvedLicense() != null) {
            final org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setId(component.getResolvedLicense().getLicenseId());
            final LicenseChoice licenseChoice = new LicenseChoice();
            licenseChoice.addLicense(license);
            cycloneComponent.setLicenseChoice(licenseChoice);
        } else if (component.getLicense() != null) {
            final org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setName(component.getLicense());
            final LicenseChoice licenseChoice = new LicenseChoice();
            licenseChoice.addLicense(license);
            cycloneComponent.setLicenseChoice(licenseChoice);
        }

        if (component.getExternalReferences() != null && component.getExternalReferences().size() > 0) {
            List<org.cyclonedx.model.ExternalReference> references = new ArrayList<>();
            for (ExternalReference ref: component.getExternalReferences()) {
                org.cyclonedx.model.ExternalReference cdxRef = new org.cyclonedx.model.ExternalReference();
                cdxRef.setType(ref.getType());
                cdxRef.setUrl(ref.getUrl());
                cdxRef.setComment(ref.getComment());
                references.add(cdxRef);
            }
            cycloneComponent.setExternalReferences(references);
        } else {
            cycloneComponent.setExternalReferences(null);
        }

        /*
        TODO: Assemble child/parent hierarchy. Components come in as flat, resolved dependencies.
         */
        /*
        if (component.getChildren() != null && component.getChildren().size() > 0) {
            final List<org.cyclonedx.model.Component> components = new ArrayList<>();
            final Component[] children = component.getChildren().toArray(new Component[0]);
            for (Component child : children) {
                components.add(convert(qm, child));
            }
            if (children.length > 0) {
                cycloneComponent.setComponents(components);
            }
        }
        */

        return cycloneComponent;
    }

    public static org.cyclonedx.model.Metadata createMetadata(final Project project) {
        final org.cyclonedx.model.Metadata metadata = new org.cyclonedx.model.Metadata();
        final org.cyclonedx.model.Tool tool = new org.cyclonedx.model.Tool();
        tool.setVendor("OWASP");
        tool.setName(alpine.Config.getInstance().getApplicationName());
        tool.setVersion(alpine.Config.getInstance().getApplicationVersion());
        metadata.setTools(Collections.singletonList(tool));
        if (project != null) {
            final org.cyclonedx.model.Component cycloneComponent = new org.cyclonedx.model.Component();
            cycloneComponent.setBomRef(project.getUuid().toString());
            cycloneComponent.setAuthor(StringUtils.trimToNull(project.getAuthor()));
            cycloneComponent.setPublisher(StringUtils.trimToNull(project.getPublisher()));
            cycloneComponent.setGroup(StringUtils.trimToNull(project.getGroup()));
            cycloneComponent.setName(StringUtils.trimToNull(project.getName()));
            if (StringUtils.trimToNull(project.getVersion()) == null) {
                cycloneComponent.setVersion("SNAPSHOT"); // Version is required per CycloneDX spec
            } else {
                cycloneComponent.setVersion(StringUtils.trimToNull(project.getVersion()));
            }
            cycloneComponent.setDescription(StringUtils.trimToNull(project.getDescription()));
            cycloneComponent.setCpe(StringUtils.trimToNull(project.getCpe()));
            if (project.getPurl() != null) {
                cycloneComponent.setPurl(StringUtils.trimToNull(project.getPurl().canonicalize()));
            }
            if (StringUtils.trimToNull(project.getSwidTagId()) != null) {
                final Swid swid = new Swid();
                swid.setTagId(StringUtils.trimToNull(project.getSwidTagId()));
                swid.setName(StringUtils.trimToNull(project.getName()));
                swid.setVersion(StringUtils.trimToNull(project.getVersion()));
                cycloneComponent.setSwid(swid);
            }
            if (project.getClassifier() != null) {
                cycloneComponent.setType(org.cyclonedx.model.Component.Type.valueOf(project.getClassifier().name()));
            } else {
                cycloneComponent.setType(org.cyclonedx.model.Component.Type.LIBRARY);
            }
            metadata.setComponent(cycloneComponent);
        }
        return metadata;
    }

    /**
     * Converts a parsed Bom to a native list of Dependency-Track component object
     * @param bom the Bom to convert
     * @return a List of Component object
     */
    public static List<ServiceComponent> convertServices(final QueryManager qm, final Bom bom, final Project project) {
        final List<ServiceComponent> services = new ArrayList<>();
        if (bom.getServices() != null) {
            for (int i = 0; i < bom.getServices().size(); i++) {
                final org.cyclonedx.model.Service cycloneDxService = bom.getServices().get(i);
                if (cycloneDxService != null) {
                    services.add(convert(qm, cycloneDxService, project));
                }
            }
        }
        return services;
    }

    public static ServiceComponent convert(final QueryManager qm, final org.cyclonedx.model.Service cycloneDxService, final Project project) {
        ServiceComponent service = qm.matchServiceIdentity(project, new ComponentIdentity(cycloneDxService));
        if (service == null) {
            service = new ServiceComponent();
            service.setProject(project);
        }
        service.setBomRef(StringUtils.trimToNull(cycloneDxService.getBomRef()));
        if (cycloneDxService.getProvider() != null) {
            OrganizationalEntity provider = new OrganizationalEntity();;
            provider.setName(cycloneDxService.getProvider().getName());
            if (cycloneDxService.getProvider().getUrls() != null && cycloneDxService.getProvider().getUrls().size() > 0) {
                provider.setUrls(cycloneDxService.getProvider().getUrls().toArray(new String[0]));
            } else {
                provider.setUrls(null);
            }
            if (cycloneDxService.getProvider().getContacts() != null) {
                List<OrganizationalContact> contacts = new ArrayList<>();
                for (org.cyclonedx.model.OrganizationalContact cycloneDxContact: cycloneDxService.getProvider().getContacts()) {
                    OrganizationalContact contact = new OrganizationalContact();
                    contact.setName(cycloneDxContact.getName());
                    contact.setEmail(cycloneDxContact.getEmail());
                    contact.setPhone(cycloneDxContact.getPhone());
                    contacts.add(contact);
                }
                provider.setContacts(contacts);
            }
            service.setProvider(provider);
        } else {
            service.setProvider(null);
        }
        service.setGroup(StringUtils.trimToNull(cycloneDxService.getGroup()));
        service.setName(StringUtils.trimToNull(cycloneDxService.getName()));
        service.setVersion(StringUtils.trimToNull(cycloneDxService.getVersion()));
        service.setDescription(StringUtils.trimToNull(cycloneDxService.getDescription()));
        if (cycloneDxService.getEndpoints() != null && cycloneDxService.getEndpoints().size() > 0) {
            service.setEndpoints(cycloneDxService.getEndpoints().toArray(new String[0]));
        } else {
            service.setEndpoints(null);
        }
        service.setAuthenticated(cycloneDxService.getAuthenticated());
        service.setCrossesTrustBoundary(cycloneDxService.getxTrustBoundary());
        if (cycloneDxService.getData() != null && cycloneDxService.getData().size() > 0) {
            List<DataClassification> dataClassifications = new ArrayList<>();
            for (org.cyclonedx.model.ServiceData data: cycloneDxService.getData()) {
                DataClassification dc = new DataClassification();
                dc.setDirection(DataClassification.Direction.valueOf(data.getFlow().name()));
                dc.setName(data.getClassification());
                dataClassifications.add(dc);
            }
            service.setData(dataClassifications);
        } else {
            service.setData(null);
        }
        if (cycloneDxService.getExternalReferences() != null && cycloneDxService.getExternalReferences().size() > 0) {
            List<ExternalReference> references = new ArrayList<>();
            for (org.cyclonedx.model.ExternalReference cycloneDxRef: cycloneDxService.getExternalReferences()) {
                ExternalReference ref = new ExternalReference();
                ref.setType(cycloneDxRef.getType());
                ref.setUrl(cycloneDxRef.getUrl());
                ref.setComment(cycloneDxRef.getComment());
                references.add(ref);
            }
            service.setExternalReferences(references);
        } else {
            service.setData(null);
        }
        /* TODO: Add when services support licenses (after component license refactor)
        final LicenseChoice licenseChoice = cycloneDxService.getLicenseChoice();
        if (licenseChoice != null && licenseChoice.getLicenses() != null && !licenseChoice.getLicenses().isEmpty()) {
            for (final org.cyclonedx.model.License cycloneLicense : licenseChoice.getLicenses()) {
                if (cycloneLicense != null) {
                    if (StringUtils.isNotBlank(cycloneLicense.getId())) {
                        final License license = qm.getLicense(StringUtils.trimToNull(cycloneLicense.getId()));
                        if (license != null) {
                            service.setResolvedLicense(license);
                        }
                    }
                    service.setLicense(StringUtils.trimToNull(cycloneLicense.getName()));
                }
            }
        }
        */
        if (cycloneDxService.getServices() != null && !cycloneDxService.getServices().isEmpty()) {
            final Collection<ServiceComponent> services = new ArrayList<>();
            for (int i = 0; i < cycloneDxService.getServices().size(); i++) {
                final org.cyclonedx.model.Service cycloneDxChildComponent = cycloneDxService.getServices().get(i);
                if (cycloneDxChildComponent != null) {
                    services.add(convert(qm, cycloneDxChildComponent, project));
                }
            }
            if (CollectionUtils.isNotEmpty(services)) {
                service.setChildren(services);
            }
        }
        return service;
    }

    public static org.cyclonedx.model.Service convert(final QueryManager qm, final ServiceComponent service) {
        final org.cyclonedx.model.Service cycloneService = new org.cyclonedx.model.Service();
        cycloneService.setBomRef(service.getUuid().toString());
        if (service.getProvider() != null) {
            org.cyclonedx.model.OrganizationalEntity cycloneEntity = new org.cyclonedx.model.OrganizationalEntity();
            cycloneEntity.setName(service.getProvider().getName());
            if (service.getProvider().getUrls() != null) {
                cycloneEntity.setUrls(Arrays.asList(service.getProvider().getUrls()));
            }
            if (service.getProvider().getContacts() != null && service.getProvider().getContacts().size() > 0) {
                List<org.cyclonedx.model.OrganizationalContact> contacts = new ArrayList<>();
                for (OrganizationalContact contact: service.getProvider().getContacts()) {
                    org.cyclonedx.model.OrganizationalContact cycloneContact = new org.cyclonedx.model.OrganizationalContact();
                    cycloneContact.setName(contact.getName());
                    cycloneContact.setEmail(contact.getEmail());
                    cycloneContact.setPhone(contact.getPhone());
                    contacts.add(cycloneContact);
                }
                cycloneEntity.setContacts(contacts);
            }
            cycloneService.setProvider(cycloneEntity);
        }
        cycloneService.setGroup(StringUtils.trimToNull(service.getGroup()));
        cycloneService.setName(StringUtils.trimToNull(service.getName()));
        cycloneService.setVersion(StringUtils.trimToNull(service.getVersion()));
        cycloneService.setDescription(StringUtils.trimToNull(service.getDescription()));
        if (service.getEndpoints() != null && service.getEndpoints().length > 0) {
            cycloneService.setEndpoints(Arrays.asList(service.getEndpoints().clone()));
        }
        cycloneService.setAuthenticated(service.getAuthenticated());
        cycloneService.setxTrustBoundary(service.getCrossesTrustBoundary());
        if (service.getData() != null && service.getData().size() > 0) {
            for (DataClassification dc: service.getData()) {
                org.cyclonedx.model.ServiceData sd = new org.cyclonedx.model.ServiceData(dc.getDirection().name(), dc.getName());
                cycloneService.addServiceData(sd);
            }
        }
        if (service.getExternalReferences() != null && service.getExternalReferences().size() > 0) {
            for (ExternalReference ref : service.getExternalReferences()) {
                org.cyclonedx.model.ExternalReference cycloneRef = new org.cyclonedx.model.ExternalReference();
                cycloneRef.setType(ref.getType());
                cycloneRef.setUrl(ref.getUrl());
                cycloneRef.setComment(ref.getComment());
                cycloneService.addExternalReference(cycloneRef);
            }
        }
        /* TODO: Add when services support licenses (after component license refactor)
        if (component.getResolvedLicense() != null) {
            final org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setId(component.getResolvedLicense().getLicenseId());
            final LicenseChoice licenseChoice = new LicenseChoice();
            licenseChoice.addLicense(license);
            cycloneComponent.setLicenseChoice(licenseChoice);
        } else if (component.getLicense() != null) {
            final org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setName(component.getLicense());
            final LicenseChoice licenseChoice = new LicenseChoice();
            licenseChoice.addLicense(license);
            cycloneComponent.setLicenseChoice(licenseChoice);
        }
        */

        /*
        TODO: Assemble child/parent hierarchy. Components come in as flat, resolved dependencies.
         */
        /*
        if (component.getChildren() != null && component.getChildren().size() > 0) {
            final List<org.cyclonedx.model.Component> components = new ArrayList<>();
            final Component[] children = component.getChildren().toArray(new Component[0]);
            for (Component child : children) {
                components.add(convert(qm, child));
            }
            if (children.length > 0) {
                cycloneComponent.setComponents(components);
            }
        }
        */
        return cycloneService;
    }

    public static org.cyclonedx.model.vulnerability.Vulnerability convert(final QueryManager qm, final CycloneDXExporter.Variant variant,
                                                                          final Finding finding) {
        final Component component = qm.getObjectByUuid(Component.class, (String)finding.getComponent().get("uuid"));
        final Project project = component.getProject();
        final Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, (String)finding.getVulnerability().get("uuid"));

        final org.cyclonedx.model.vulnerability.Vulnerability cdxVulnerability = new org.cyclonedx.model.vulnerability.Vulnerability();
        cdxVulnerability.setBomRef(vulnerability.getUuid().toString());
        cdxVulnerability.setId(vulnerability.getVulnId());
        // Add the vulnerability source
        org.cyclonedx.model.vulnerability.Vulnerability.Source cdxSource = new org.cyclonedx.model.vulnerability.Vulnerability.Source();
        cdxSource.setName(vulnerability.getSource());
        cdxVulnerability.setSource(convertDtVulnSourceToCdxVulnSource(Vulnerability.Source.valueOf(vulnerability.getSource())));
        if (vulnerability.getCvssV2BaseScore() != null) {
            org.cyclonedx.model.vulnerability.Vulnerability.Rating rating = new org.cyclonedx.model.vulnerability.Vulnerability.Rating();
            rating.setSource(convertDtVulnSourceToCdxVulnSource(Vulnerability.Source.valueOf(vulnerability.getSource())));
            rating.setMethod(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method.CVSSV2);
            rating.setScore(vulnerability.getCvssV2BaseScore().doubleValue());
            rating.setVector(vulnerability.getCvssV2Vector());
            if (rating.getScore() >= 7.0) {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.HIGH);
            } else if (rating.getScore() >= 4.0) {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.MEDIUM);
            } else {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.LOW);
            }
            cdxVulnerability.addRating(rating);
        }
        if (vulnerability.getCvssV3BaseScore() != null) {
            org.cyclonedx.model.vulnerability.Vulnerability.Rating rating = new org.cyclonedx.model.vulnerability.Vulnerability.Rating();
            rating.setSource(convertDtVulnSourceToCdxVulnSource(Vulnerability.Source.valueOf(vulnerability.getSource())));
            if (vulnerability.getCvssV3Vector() != null && vulnerability.getCvssV3Vector().contains("CVSS:3.0")) {
                rating.setMethod(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method.CVSSV3);
            } else {
                rating.setMethod(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method.CVSSV31);
            }
            rating.setScore(vulnerability.getCvssV3BaseScore().doubleValue());
            rating.setVector(vulnerability.getCvssV3Vector());
            if (rating.getScore() >= 9.0) {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.CRITICAL);
            } else if (rating.getScore() >= 7.0) {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.HIGH);
            } else if (rating.getScore() >= 4.0) {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.MEDIUM);
            } else {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.LOW);
            }
            cdxVulnerability.addRating(rating);
        }
        if (vulnerability.getCvssV2BaseScore() == null && vulnerability.getCvssV3BaseScore() == null) {
            org.cyclonedx.model.vulnerability.Vulnerability.Rating rating = new org.cyclonedx.model.vulnerability.Vulnerability.Rating();
            rating.setSeverity(convertDtSeverityToCdxSeverity(vulnerability.getSeverity()));
            rating.setSource(convertDtVulnSourceToCdxVulnSource(Vulnerability.Source.valueOf(vulnerability.getSource())));
            rating.setMethod(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method.OTHER);
            cdxVulnerability.addRating(rating);
        }
        if (vulnerability.getCwes() != null) {
            for (final Integer cweId: vulnerability.getCwes()) {
                final Cwe cwe = CweResolver.getInstance().lookup(cweId);
                if (cwe != null) {
                    cdxVulnerability.addCwe(cwe.getCweId());
                }
            }
        }
        cdxVulnerability.setDescription(vulnerability.getDescription());
        cdxVulnerability.setRecommendation(vulnerability.getRecommendation());
        cdxVulnerability.setCreated(vulnerability.getCreated());
        cdxVulnerability.setPublished(vulnerability.getPublished());
        cdxVulnerability.setUpdated(vulnerability.getUpdated());

        if (CycloneDXExporter.Variant.INVENTORY_WITH_VULNERABILITIES == variant) {
            final List<org.cyclonedx.model.vulnerability.Vulnerability.Affect> affects = new ArrayList<>();
            final org.cyclonedx.model.vulnerability.Vulnerability.Affect affect = new org.cyclonedx.model.vulnerability.Vulnerability.Affect();
            affect.setRef(component.getUuid().toString());
            affects.add(affect);
            cdxVulnerability.setAffects(affects);
        } else if (CycloneDXExporter.Variant.VEX == variant && project != null) {
            final Analysis analysis = qm.getAnalysis(
                    qm.getObjectByUuid(Component.class, component.getUuid()),
                    qm.getObjectByUuid(Vulnerability.class, vulnerability.getUuid())
            );
            if (analysis != null) {
                final org.cyclonedx.model.vulnerability.Vulnerability.Analysis cdxAnalysis = new org.cyclonedx.model.vulnerability.Vulnerability.Analysis();
                if (analysis.getAnalysisResponse() != null) {
                    final org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response response = convertDtVulnAnalysisResponseToCdxAnalysisResponse(analysis.getAnalysisResponse());
                    if (response != null) {
                        List<org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response> responses = new ArrayList<>();
                        responses.add(response);
                        cdxAnalysis.setResponses(responses);
                    }
                }
                if (analysis.getAnalysisState() != null) {
                    cdxAnalysis.setState(convertDtVulnAnalysisStateToCdxAnalysisState(analysis.getAnalysisState()));
                }
                if (analysis.getAnalysisJustification() != null) {
                    cdxAnalysis.setJustification(convertDtVulnAnalysisJustificationToCdxAnalysisJustification(analysis.getAnalysisJustification()));
                }
                cdxAnalysis.setDetail(StringUtils.trimToNull(analysis.getAnalysisDetails()));
                cdxVulnerability.setAnalysis(cdxAnalysis);
            }

            final List<org.cyclonedx.model.vulnerability.Vulnerability.Affect> affects = new ArrayList<>();
            final org.cyclonedx.model.vulnerability.Vulnerability.Affect affect = new org.cyclonedx.model.vulnerability.Vulnerability.Affect();
            affect.setRef(project.getUuid().toString());
            affects.add(affect);
            cdxVulnerability.setAffects(affects);
        }
        return cdxVulnerability;
    }

    /**
     * Converts a parsed Bom to a native list of Dependency-Track component object
     * @param bom the Bom to convert
     * @return a List of Component object
     */
    public static void generateDependencies(final QueryManager qm, final Bom bom, final Project project, final List<Component> components) {
        // Get direct dependencies first
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null && bom.getMetadata().getComponent().getBomRef() != null) {
            final String targetBomRef = bom.getMetadata().getComponent().getBomRef();
            final org.cyclonedx.model.Dependency targetDep = getDependencyFromBomRef(targetBomRef, bom.getDependencies());
            final JSONArray jsonArray = new JSONArray();
            if (targetDep != null && targetDep.getDependencies() != null) {
                for (final org.cyclonedx.model.Dependency directDep : targetDep.getDependencies()) {
                    final Component c = getComponentFromBomRef(directDep.getRef(), components);
                    if (c != null) {
                        final ComponentIdentity ci = new ComponentIdentity(c);
                        jsonArray.put(ci.toJSON());
                    }
                }
            }
            if (jsonArray.isEmpty()) {
                project.setDirectDependencies(null);
            } else {
                project.setDirectDependencies(jsonArray.toString());
            }
        }
        // Get transitive last. It is possible that some CycloneDX implementations may not properly specify direct
        // dependencies. As a result, it is not possible to distinguish between direct and transitive.
        for (final Component c1: components) {
            if (c1.getBomRef() != null) {
                final JSONArray jsonArray = new JSONArray();
                final org.cyclonedx.model.Dependency d1 = getDependencyFromBomRef(c1.getBomRef(), bom.getDependencies());
                if (d1 != null && d1.getDependencies() != null) {
                    for (final org.cyclonedx.model.Dependency d2: d1.getDependencies()) {
                        final Component c2 = getComponentFromBomRef(d2.getRef(), components);
                        if (c2 != null) {
                            final ComponentIdentity ci = new ComponentIdentity(c2);
                            jsonArray.put(ci.toJSON());
                        }
                    }
                }
                if (jsonArray.isEmpty()) {
                    c1.setDirectDependencies(null);
                } else {
                    c1.setDirectDependencies(jsonArray.toString());
                }
            }
        }
    }

    private static Component getComponentFromBomRef(final String bomRef, final List<Component> components) {
        if (components != null) {
            for (Component c : components) {
                if (bomRef != null && bomRef.equals(c.getBomRef())) {
                    return c;
                }
            }
        }
        return null;
    }

    private static org.cyclonedx.model.Dependency getDependencyFromBomRef(final String bomRef, final List<org.cyclonedx.model.Dependency> dependencies) {
        if (dependencies != null) {
            for (Dependency o : dependencies) {
                if (bomRef != null && bomRef.equals(o.getRef())) {
                    return o;
                }
            }
        }
        return null;
    }

    private static org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity convertDtSeverityToCdxSeverity(final Severity severity) {
        switch (severity) {
            case CRITICAL:
                return org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.CRITICAL;
            case HIGH:
                return org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.HIGH;
            case MEDIUM:
                return org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.MEDIUM;
            case LOW:
                return org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.LOW;
            default:
                return org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.UNKNOWN;
        }
    }

    private static org.cyclonedx.model.vulnerability.Vulnerability.Source convertDtVulnSourceToCdxVulnSource(final Vulnerability.Source vulnSource) {
        org.cyclonedx.model.vulnerability.Vulnerability.Source cdxSource = new org.cyclonedx.model.vulnerability.Vulnerability.Source();
        cdxSource.setName(vulnSource.name());
        switch (vulnSource) {
            case NVD:
                cdxSource.setUrl("https://nvd.nist.gov/"); break;
            case NPM:
                cdxSource.setUrl("https://www.npmjs.com/"); break;
            case GITHUB:
                cdxSource.setUrl("https://github.com/advisories"); break;
            case VULNDB:
                cdxSource.setUrl("https://vulndb.cyberriskanalytics.com/"); break;
            case OSSINDEX:
                cdxSource.setUrl("https://ossindex.sonatype.org/"); break;
            case RETIREJS:
                cdxSource.setUrl("https://github.com/RetireJS/retire.js"); break;
        }
        return cdxSource;
    }

    private static org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response convertDtVulnAnalysisResponseToCdxAnalysisResponse(final AnalysisResponse analysisResponse) {
        if (analysisResponse == null) {
            return null;
        }
        switch (analysisResponse) {
            case UPDATE:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response.UPDATE;
            case CAN_NOT_FIX:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response.CAN_NOT_FIX;
            case WILL_NOT_FIX:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response.WILL_NOT_FIX;
            case ROLLBACK:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response.ROLLBACK;
            case WORKAROUND_AVAILABLE:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response.WORKAROUND_AVAILABLE;
            default:
                return null;
        }
    }

    public static AnalysisResponse convertCdxVulnAnalysisResponseToDtAnalysisResponse(final org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response cdxAnalysisResponse) {
        if (cdxAnalysisResponse == null) {
            return null;
        }
        switch (cdxAnalysisResponse) {
            case UPDATE:
                return AnalysisResponse.UPDATE;
            case CAN_NOT_FIX:
                return AnalysisResponse.CAN_NOT_FIX;
            case WILL_NOT_FIX:
                return AnalysisResponse.WILL_NOT_FIX;
            case ROLLBACK:
                return AnalysisResponse.ROLLBACK;
            case WORKAROUND_AVAILABLE:
                return AnalysisResponse.WORKAROUND_AVAILABLE;
            default:
                return AnalysisResponse.NOT_SET;
        }
    }

    private static org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State convertDtVulnAnalysisStateToCdxAnalysisState(final AnalysisState analysisState) {
        if (analysisState == null) {
            return null;
        }
        switch (analysisState) {
            case EXPLOITABLE:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State.EXPLOITABLE;
            case FALSE_POSITIVE:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State.FALSE_POSITIVE;
            case IN_TRIAGE:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State.IN_TRIAGE;
            case NOT_AFFECTED:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State.NOT_AFFECTED;
            case RESOLVED:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State.RESOLVED;
            default:
                return null;
        }
    }

    public static AnalysisState convertCdxVulnAnalysisStateToDtAnalysisState(final org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State cdxAnalysisState) {
        if (cdxAnalysisState == null) {
            return null;
        }
        switch (cdxAnalysisState) {
            case EXPLOITABLE:
                return AnalysisState.EXPLOITABLE;
            case FALSE_POSITIVE:
                return AnalysisState.FALSE_POSITIVE;
            case IN_TRIAGE:
                return AnalysisState.IN_TRIAGE;
            case NOT_AFFECTED:
                return AnalysisState.NOT_AFFECTED;
            case RESOLVED:
                return AnalysisState.RESOLVED;
            default:
                return AnalysisState.NOT_SET;
        }
    }

    private static org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification convertDtVulnAnalysisJustificationToCdxAnalysisJustification(final AnalysisJustification analysisJustification) {
        if (analysisJustification == null) {
            return null;
        }
        switch (analysisJustification) {
            case CODE_NOT_PRESENT:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.CODE_NOT_PRESENT;
            case CODE_NOT_REACHABLE:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.CODE_NOT_REACHABLE;
            case PROTECTED_AT_PERIMETER:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.PROTECTED_AT_PERIMETER;
            case PROTECTED_AT_RUNTIME:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.PROTECTED_AT_RUNTIME;
            case PROTECTED_BY_COMPILER:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.PROTECTED_BY_COMPILER;
            case PROTECTED_BY_MITIGATING_CONTROL:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.PROTECTED_BY_MITIGATING_CONTROL;
            case REQUIRES_CONFIGURATION:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.REQUIRES_CONFIGURATION;
            case REQUIRES_DEPENDENCY:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.REQUIRES_DEPENDENCY;
            case REQUIRES_ENVIRONMENT:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.REQUIRES_ENVIRONMENT;
            default:
                return null;
        }
    }

    public static AnalysisJustification convertCdxVulnAnalysisJustificationToDtAnalysisJustification(final org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification cdxAnalysisJustification) {
        if (cdxAnalysisJustification == null) {
            return null;
        }
        switch (cdxAnalysisJustification) {
            case CODE_NOT_PRESENT:
                return AnalysisJustification.CODE_NOT_PRESENT;
            case CODE_NOT_REACHABLE:
                return AnalysisJustification.CODE_NOT_REACHABLE;
            case PROTECTED_AT_PERIMETER:
                return AnalysisJustification.PROTECTED_AT_PERIMETER;
            case PROTECTED_AT_RUNTIME:
                return AnalysisJustification.PROTECTED_AT_RUNTIME;
            case PROTECTED_BY_COMPILER:
                return AnalysisJustification.PROTECTED_BY_COMPILER;
            case PROTECTED_BY_MITIGATING_CONTROL:
                return AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL;
            case REQUIRES_CONFIGURATION:
                return AnalysisJustification.REQUIRES_CONFIGURATION;
            case REQUIRES_DEPENDENCY:
                return AnalysisJustification.REQUIRES_DEPENDENCY;
            case REQUIRES_ENVIRONMENT:
                return AnalysisJustification.REQUIRES_ENVIRONMENT;
            default:
                return AnalysisJustification.NOT_SET;
        }
    }
}
