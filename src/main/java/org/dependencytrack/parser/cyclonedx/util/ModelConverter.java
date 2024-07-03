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
package org.dependencytrack.parser.cyclonedx.util;

import alpine.common.logging.Logger;
import alpine.model.IConfigProperty;
import alpine.model.IConfigProperty.PropertyType;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.model.BomReference;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Swid;
import org.cyclonedx.model.license.Expression;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.DataClassification;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.cyclonedx.CycloneDXExporter;
import org.dependencytrack.parser.spdx.expression.SpdxExpressionParser;
import org.dependencytrack.parser.spdx.expression.model.SpdxExpression;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.VulnerabilityUtil;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.trim;
import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.dependencytrack.util.PurlUtil.silentPurlCoordinatesOnly;

public class ModelConverter {

    private static final Logger LOGGER = Logger.getLogger(ModelConverter.class);

    /**
     * Private Constructor.
     */
    private ModelConverter() {
    }

    public static ProjectMetadata convertToProjectMetadata(final org.cyclonedx.model.Metadata cdxMetadata) {
        if (cdxMetadata == null) {
            return null;
        }

        final var projectMetadata = new ProjectMetadata();
        projectMetadata.setAuthors(convertCdxContacts(cdxMetadata.getAuthors()));
        projectMetadata.setSupplier(convert(cdxMetadata.getSupplier()));

        return projectMetadata;
    }

    public static Project convertToProject(final org.cyclonedx.model.Metadata cdxMetadata) {
        if (cdxMetadata == null || cdxMetadata.getComponent() == null) {
            return null;
        }

        final Project project = convertToProject(cdxMetadata.getComponent());
        project.setManufacturer(convert(cdxMetadata.getManufacture()));

        return project;
    }

    public static Project convertToProject(final org.cyclonedx.model.Component cdxComponent) {
        final var project = new Project();
        project.setBomRef(useOrGenerateRandomBomRef(cdxComponent.getBomRef()));
        project.setAuthor(trimToNull(cdxComponent.getAuthor()));
        project.setPublisher(trimToNull(cdxComponent.getPublisher()));
        project.setSupplier(convert(cdxComponent.getSupplier()));
        project.setClassifier(convertClassifier(cdxComponent.getType()).orElse(Classifier.APPLICATION));
        project.setGroup(trimToNull(cdxComponent.getGroup()));
        project.setName(trimToNull(cdxComponent.getName()));
        project.setVersion(trimToNull(cdxComponent.getVersion()));
        project.setDescription(trimToNull(cdxComponent.getDescription()));
        project.setExternalReferences(convertExternalReferences(cdxComponent.getExternalReferences()));

        if (cdxComponent.getPurl() != null) {
            try {
                final var purl = new PackageURL(cdxComponent.getPurl());
                project.setPurl(purl);
            } catch (MalformedPackageURLException e) {
                LOGGER.debug("Encountered invalid PURL", e);
            }
        }

        if (cdxComponent.getSwid() != null) {
            project.setSwidTagId(trimToNull(cdxComponent.getSwid().getTagId()));
        }

        return project;
    }

    public static List<Component> convertComponents(final List<org.cyclonedx.model.Component> cdxComponents) {
        if (cdxComponents == null || cdxComponents.isEmpty()) {
            return Collections.emptyList();
        }

        return cdxComponents.stream().map(ModelConverter::convertComponent).toList();
    }

    public static Component convertComponent(final org.cyclonedx.model.Component cdxComponent) {
        final var component = new Component();
        component.setBomRef(useOrGenerateRandomBomRef(cdxComponent.getBomRef()));
        component.setAuthor(trimToNull(cdxComponent.getAuthor()));
        component.setPublisher(trimToNull(cdxComponent.getPublisher()));
        component.setSupplier(convert(cdxComponent.getSupplier()));
        component.setClassifier(convertClassifier(cdxComponent.getType()).orElse(Classifier.LIBRARY));
        component.setGroup(trimToNull(cdxComponent.getGroup()));
        component.setName(trimToNull(cdxComponent.getName()));
        component.setVersion(trimToNull(cdxComponent.getVersion()));
        component.setDescription(trimToNull(cdxComponent.getDescription()));
        component.setCopyright(trimToNull(cdxComponent.getCopyright()));
        component.setCpe(trimToNull(cdxComponent.getCpe()));
        component.setExternalReferences(convertExternalReferences(cdxComponent.getExternalReferences()));
        component.setProperties(convertToComponentProperties(cdxComponent.getProperties()));

        if (cdxComponent.getPurl() != null) {
            try {
                final var purl = new PackageURL(cdxComponent.getPurl());
                component.setPurl(purl);
                component.setPurlCoordinates(silentPurlCoordinatesOnly(purl));
            } catch (MalformedPackageURLException e) {
                LOGGER.debug("Encountered invalid PURL", e);
            }
        }

        if (cdxComponent.getSwid() != null) {
            component.setSwidTagId(trimToNull(cdxComponent.getSwid().getTagId()));
        }

        if (cdxComponent.getHashes() != null && !cdxComponent.getHashes().isEmpty()) {
            for (final org.cyclonedx.model.Hash cdxHash : cdxComponent.getHashes()) {
                final Consumer<String> hashSetter = switch (cdxHash.getAlgorithm().toLowerCase()) {
                    case "md5" -> component::setMd5;
                    case "sha-1" -> component::setSha1;
                    case "sha-256" -> component::setSha256;
                    case "sha-384" -> component::setSha384;
                    case "sha-512" -> component::setSha512;
                    case "sha3-256" -> component::setSha3_256;
                    case "sha3-384" -> component::setSha3_384;
                    case "sha3-512" -> component::setSha3_512;
                    case "blake2b-256" -> component::setBlake2b_256;
                    case "blake2b-384" -> component::setBlake2b_384;
                    case "blake2b-512" -> component::setBlake2b_512;
                    case "blake3" -> component::setBlake3;
                    default -> null;
                };
                if (hashSetter != null) {
                    hashSetter.accept(cdxHash.getValue());
                }
            }
        }

        final var licenseCandidates = new ArrayList<org.cyclonedx.model.License>();
        if (cdxComponent.getLicenseChoice() != null) {
            if (cdxComponent.getLicenseChoice().getLicenses() != null) {
                cdxComponent.getLicenseChoice().getLicenses().stream()
                        .filter(license -> isNotBlank(license.getId()) || isNotBlank(license.getName()))
                        .peek(license -> {
                            // License text can be large, but we don't need it for further processing. Drop it.
                            license.setLicenseText(null);
                        })
                        .forEach(licenseCandidates::add);
            }

            final Expression licenseExpression = cdxComponent.getLicenseChoice().getExpression();
            if (licenseExpression != null && isNotBlank(licenseExpression.getValue())) {
                // If the expression consists of just one license ID, add it as another option.
                final var expressionParser = new SpdxExpressionParser();
                final SpdxExpression expression = expressionParser.parse(licenseExpression.getValue());
                if (!SpdxExpression.INVALID.equals(expression)) {
                    component.setLicenseExpression(trim(licenseExpression.getValue()));

                    if (expression.getSpdxLicenseId() != null) {
                        final var expressionLicense = new org.cyclonedx.model.License();
                        expressionLicense.setId(expression.getSpdxLicenseId());
                        expressionLicense.setName(expression.getSpdxLicenseId());
                        licenseCandidates.add(expressionLicense);
                    }
                } else {
                    LOGGER.warn("""
                            Encountered invalid license expression "%s" for \
                            Component{group=%s, name=%s, version=%s, bomRef=%s}; Skipping\
                            """.formatted(cdxComponent.getLicenseChoice().getExpression(), component.getGroup(),
                            component.getName(), component.getVersion(), component.getBomRef()));
                }
            }
        }
        component.setLicenseCandidates(licenseCandidates);

        if (cdxComponent.getComponents() != null && !cdxComponent.getComponents().isEmpty()) {
            final var children = new ArrayList<Component>();

            for (final org.cyclonedx.model.Component cdxChildComponent : cdxComponent.getComponents()) {
                children.add(convertComponent(cdxChildComponent));
            }

            component.setChildren(children);
        }

        return component;
    }

    private static List<ComponentProperty> convertToComponentProperties(final List<org.cyclonedx.model.Property> cdxProperties) {
        if (cdxProperties == null || cdxProperties.isEmpty()) {
            return Collections.emptyList();
        }

        final var identitiesSeen = new HashSet<ComponentProperty.Identity>();
        return cdxProperties.stream()
                .map(ModelConverter::convertToComponentProperty)
                .filter(Objects::nonNull)
                .filter(property -> identitiesSeen.add(new ComponentProperty.Identity(property)))
                .toList();
    }

    private static ComponentProperty convertToComponentProperty(final org.cyclonedx.model.Property cdxProperty) {
        if (cdxProperty == null) {
            return null;
        }

        final var property = new ComponentProperty();
        property.setPropertyValue(trimToNull(cdxProperty.getValue()));
        property.setPropertyType(PropertyType.STRING);

        final String cdxPropertyName = trimToNull(cdxProperty.getName());
        if (cdxPropertyName == null) {
            return null;
        }

        // Treat property names according to the CycloneDX namespace syntax:
        // https://cyclonedx.github.io/cyclonedx-property-taxonomy/
        final int firstSeparatorIndex = cdxPropertyName.indexOf(':');
        if (firstSeparatorIndex < 0) {
            property.setPropertyName(cdxPropertyName);
        } else {
            property.setGroupName(cdxPropertyName.substring(0, firstSeparatorIndex));
            property.setPropertyName(cdxPropertyName.substring(firstSeparatorIndex + 1));
        }

        return property;
    }

    public static List<ServiceComponent> convertServices(final List<org.cyclonedx.model.Service> cdxServices) {
        if (cdxServices == null || cdxServices.isEmpty()) {
            return Collections.emptyList();
        }

        return cdxServices.stream().map(ModelConverter::convertService).toList();
    }

    public static ServiceComponent convertService(final org.cyclonedx.model.Service cdxService) {
        final var service = new ServiceComponent();
        service.setBomRef(useOrGenerateRandomBomRef(cdxService.getBomRef()));
        service.setGroup(trimToNull(cdxService.getGroup()));
        service.setName(trimToNull(cdxService.getName()));
        service.setVersion(trimToNull(cdxService.getVersion()));
        service.setDescription(trimToNull(cdxService.getDescription()));
        service.setAuthenticated(cdxService.getAuthenticated());
        service.setCrossesTrustBoundary(cdxService.getxTrustBoundary());
        service.setExternalReferences(convertExternalReferences(cdxService.getExternalReferences()));
        service.setProvider(convertOrganizationalEntity(cdxService.getProvider()));
        service.setData(convertDataClassification(cdxService.getData()));

        if (cdxService.getEndpoints() != null && !cdxService.getEndpoints().isEmpty()) {
            service.setEndpoints(cdxService.getEndpoints().toArray(new String[0]));
        }

        if (cdxService.getServices() != null && !cdxService.getServices().isEmpty()) {
            final var children = new ArrayList<ServiceComponent>();

            for (final org.cyclonedx.model.Service cdxChildService : cdxService.getServices()) {
                children.add(convertService(cdxChildService));
            }

            service.setChildren(children);
        }

        return service;
    }

    public static MultiValuedMap<String, String> convertDependencyGraph(final List<Dependency> cdxDependencies) {
        final var dependencyGraph = new HashSetValuedHashMap<String, String>();
        if (cdxDependencies == null || cdxDependencies.isEmpty()) {
            return dependencyGraph;
        }

        for (final Dependency cdxDependency : cdxDependencies) {
            if (cdxDependency.getDependencies() == null || cdxDependency.getDependencies().isEmpty()) {
                continue;
            }

            final List<String> directDependencies = cdxDependency.getDependencies().stream()
                    .map(BomReference::getRef).toList();
            dependencyGraph.putAll(cdxDependency.getRef(), directDependencies);
        }

        return dependencyGraph;
    }

    private static Optional<Classifier> convertClassifier(final org.cyclonedx.model.Component.Type cdxComponentType) {
        return Optional.ofNullable(cdxComponentType)
                .map(Enum::name)
                .map(Classifier::valueOf);
    }

    private static List<ExternalReference> convertExternalReferences(final List<org.cyclonedx.model.ExternalReference> cdxExternalReferences) {
        if (cdxExternalReferences == null || cdxExternalReferences.isEmpty()) {
            return null;
        }

        return cdxExternalReferences.stream()
                .map(cdxExternalReference -> {
                    final var externalReference = new ExternalReference();
                    externalReference.setType(cdxExternalReference.getType());
                    externalReference.setUrl(cdxExternalReference.getUrl());
                    externalReference.setComment(cdxExternalReference.getComment());
                    return externalReference;
                })
                .toList();
    }

    private static OrganizationalEntity convertOrganizationalEntity(final org.cyclonedx.model.OrganizationalEntity cdxEntity) {
        if (cdxEntity == null) {
            return null;
        }

        final var entity = new OrganizationalEntity();
        entity.setName(cdxEntity.getName());

        if (cdxEntity.getUrls() != null && !cdxEntity.getUrls().isEmpty()) {
            entity.setUrls(cdxEntity.getUrls().toArray(new String[0]));
        }

        if (cdxEntity.getContacts() != null && !cdxEntity.getContacts().isEmpty()) {
            final var contacts = new ArrayList<OrganizationalContact>();
            for (final org.cyclonedx.model.OrganizationalContact cdxContact : cdxEntity.getContacts()) {
                final var contact = new OrganizationalContact();
                contact.setName(cdxContact.getName());
                contact.setEmail(cdxContact.getEmail());
                contact.setPhone(cdxContact.getPhone());
                contacts.add(contact);
            }
            entity.setContacts(contacts);
        }

        return entity;
    }

    private static List<DataClassification> convertDataClassification(final List<org.cyclonedx.model.ServiceData> cdxData) {
        if (cdxData == null || cdxData.isEmpty()) {
            return Collections.emptyList();
        }

        return cdxData.stream()
                .map(cdxDatum -> {
                    final var classification = new DataClassification();
                    classification.setName(cdxDatum.getClassification());
                    classification.setDirection(DataClassification.Direction.valueOf(cdxDatum.getFlow().name()));
                    return classification;
                })
                .toList();
    }

    private static String useOrGenerateRandomBomRef(final String bomRef) {
        return Optional.ofNullable(bomRef)
                .map(StringUtils::trimToNull)
                .orElseGet(() -> UUID.randomUUID().toString());
    }

    public static <T> List<T> flatten(final Collection<T> items,
                                      final Function<T, Collection<T>> childrenGetter,
                                      final BiConsumer<T, Collection<T>> childrenSetter) {
        final var result = new ArrayList<T>();
        if (items == null || items.isEmpty()) {
            return Collections.emptyList();
        }

        for (final T item : items) {
            final Collection<T> children = childrenGetter.apply(item);
            if (children != null) {
                result.addAll(flatten(children, childrenGetter, childrenSetter));
                childrenSetter.accept(item, null);
            }

            result.add(item);
        }

        return result;
    }

    public static OrganizationalEntity convert(final org.cyclonedx.model.OrganizationalEntity cdxEntity) {
        if (cdxEntity == null) {
            return null;
        }

        final var dtEntity = new OrganizationalEntity();
        dtEntity.setName(StringUtils.trimToNull(cdxEntity.getName()));
        if (cdxEntity.getContacts() != null && !cdxEntity.getContacts().isEmpty()) {
            dtEntity.setContacts(cdxEntity.getContacts().stream().map(ModelConverter::convert).toList());
        }
        if (cdxEntity.getUrls() != null && !cdxEntity.getUrls().isEmpty()) {
            dtEntity.setUrls(cdxEntity.getUrls().toArray(new String[0]));
        }

        return dtEntity;
    }

    public static List<OrganizationalContact> convertCdxContacts(final List<org.cyclonedx.model.OrganizationalContact> cdxContacts) {
        if (cdxContacts == null) {
            return null;
        }

        return cdxContacts.stream().map(ModelConverter::convert).toList();
    }

    private static OrganizationalContact convert(final org.cyclonedx.model.OrganizationalContact cdxContact) {
        if (cdxContact == null) {
            return null;
        }

        final var dtContact = new OrganizationalContact();
        dtContact.setName(StringUtils.trimToNull(cdxContact.getName()));
        dtContact.setEmail(StringUtils.trimToNull(cdxContact.getEmail()));
        dtContact.setPhone(StringUtils.trimToNull(cdxContact.getPhone()));
        return dtContact;
    }

    private static List<org.cyclonedx.model.OrganizationalContact> convertContacts(final List<OrganizationalContact> dtContacts) {
        if (dtContacts == null) {
            return null;
        }

        return dtContacts.stream().map(ModelConverter::convert).toList();
    }

    private static org.cyclonedx.model.OrganizationalEntity convert(final OrganizationalEntity dtEntity) {
        if (dtEntity == null) {
            return null;
        }

        final var cdxEntity = new org.cyclonedx.model.OrganizationalEntity();
        cdxEntity.setName(StringUtils.trimToNull(dtEntity.getName()));
        if (dtEntity.getContacts() != null && !dtEntity.getContacts().isEmpty()) {
            cdxEntity.setContacts(dtEntity.getContacts().stream().map(ModelConverter::convert).toList());
        }
        if (dtEntity.getUrls() != null && dtEntity.getUrls().length > 0) {
            cdxEntity.setUrls(Arrays.stream(dtEntity.getUrls()).toList());
        }

        return cdxEntity;
    }

    private static org.cyclonedx.model.OrganizationalContact convert(final OrganizationalContact dtContact) {
        if (dtContact == null) {
            return null;
        }

        final var cdxContact = new org.cyclonedx.model.OrganizationalContact();
        cdxContact.setName(StringUtils.trimToNull(dtContact.getName()));
        cdxContact.setEmail(StringUtils.trimToNull(dtContact.getEmail()));
        cdxContact.setPhone(StringUtils.trimToNull(cdxContact.getPhone()));
        return cdxContact;
    }

    /**Convert from DT to CycloneDX */
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
        cycloneComponent.setSupplier(convert(component.getSupplier()));
        cycloneComponent.setProperties(convert(component.getProperties()));

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

        final LicenseChoice licenseChoice = new LicenseChoice();
        if (component.getResolvedLicense() != null) {
            final org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            if(!component.getResolvedLicense().isCustomLicense()){
                license.setId(component.getResolvedLicense().getLicenseId());
            } else{
                license.setName(component.getResolvedLicense().getName());
            }
            license.setUrl(component.getLicenseUrl());
            licenseChoice.addLicense(license);
            cycloneComponent.setLicenseChoice(licenseChoice);
        } else if (component.getLicense() != null) {
            final org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setName(component.getLicense());
            license.setUrl(component.getLicenseUrl());
            licenseChoice.addLicense(license);
            cycloneComponent.setLicenseChoice(licenseChoice);
        } else if (StringUtils.isNotEmpty(component.getLicenseUrl())) {
            final org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setUrl(component.getLicenseUrl());
            licenseChoice.addLicense(license);
            cycloneComponent.setLicenseChoice(licenseChoice);
        }
        if (component.getLicenseExpression() != null) {
            final var licenseExpression = new Expression();
            licenseExpression.setValue(component.getLicenseExpression());
            licenseChoice.setExpression(licenseExpression);
            cycloneComponent.setLicenseChoice(licenseChoice);
        }


        if (component.getExternalReferences() != null && !component.getExternalReferences().isEmpty()) {
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

    private static <T extends IConfigProperty> List<org.cyclonedx.model.Property> convert(final Collection<T> dtProperties) {
        if (dtProperties == null || dtProperties.isEmpty()) {
            return Collections.emptyList();
        }

        final List<org.cyclonedx.model.Property> cdxProperties = new ArrayList<>();
        for (final T dtProperty : dtProperties) {
            if (dtProperty.getPropertyType() == PropertyType.ENCRYPTEDSTRING) {
                // We treat encrypted properties as internal.
                // They shall not be leaked when exporting.
                continue;
            }

            final var cdxProperty = new org.cyclonedx.model.Property();
            if (dtProperty.getGroupName() == null) {
                cdxProperty.setName(dtProperty.getPropertyName());
            } else {
                cdxProperty.setName("%s:%s".formatted(dtProperty.getGroupName(), dtProperty.getPropertyName()));
            }
            cdxProperty.setValue(dtProperty.getPropertyValue());
            cdxProperties.add(cdxProperty);
        }

        return cdxProperties;
    }

    public static org.cyclonedx.model.Metadata createMetadata(final Project project) {
        final org.cyclonedx.model.Metadata metadata = new org.cyclonedx.model.Metadata();
        final org.cyclonedx.model.Tool tool = new org.cyclonedx.model.Tool();
        tool.setVendor("OWASP");
        tool.setName(alpine.Config.getInstance().getApplicationName());
        tool.setVersion(alpine.Config.getInstance().getApplicationVersion());
        metadata.setTools(Collections.singletonList(tool));
        if (project != null) {
            metadata.setManufacture(convert(project.getManufacturer()));

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
            if (project.getExternalReferences() != null && !project.getExternalReferences().isEmpty()) {
                List<org.cyclonedx.model.ExternalReference> references = new ArrayList<>();
                project.getExternalReferences().forEach(externalReference -> {
                    org.cyclonedx.model.ExternalReference ref = new org.cyclonedx.model.ExternalReference();
                    ref.setUrl(externalReference.getUrl());
                    ref.setType(externalReference.getType());
                    ref.setComment(externalReference.getComment());
                    references.add(ref);
                });
                cycloneComponent.setExternalReferences(references);
            }
            cycloneComponent.setSupplier(convert(project.getSupplier()));

            // NB: Project properties are currently used to configure integrations
            // such as Defect Dojo. They can also contain encrypted values that most
            // definitely are not safe to share. Before we can include project properties
            // in BOM exports, we need a filtering mechanism.
            // cycloneComponent.setProperties(convert(project.getProperties()));

            metadata.setComponent(cycloneComponent);

            if (project.getMetadata() != null) {
                metadata.setAuthors(convertContacts(project.getMetadata().getAuthors()));
                metadata.setSupplier(convert(project.getMetadata().getSupplier()));
            }
        }
        return metadata;
    }

    public static org.cyclonedx.model.Service convert(final QueryManager qm, final ServiceComponent service) {
        final org.cyclonedx.model.Service cycloneService = new org.cyclonedx.model.Service();
        cycloneService.setBomRef(service.getUuid().toString());
        cycloneService.setProvider(convert(service.getProvider()));
        cycloneService.setGroup(StringUtils.trimToNull(service.getGroup()));
        cycloneService.setName(StringUtils.trimToNull(service.getName()));
        cycloneService.setVersion(StringUtils.trimToNull(service.getVersion()));
        cycloneService.setDescription(StringUtils.trimToNull(service.getDescription()));
        if (service.getEndpoints() != null && service.getEndpoints().length > 0) {
            cycloneService.setEndpoints(Arrays.asList(service.getEndpoints().clone()));
        }
        cycloneService.setAuthenticated(service.getAuthenticated());
        cycloneService.setxTrustBoundary(service.getCrossesTrustBoundary());
        if (service.getData() != null && !service.getData().isEmpty()) {
            for (DataClassification dc: service.getData()) {
                org.cyclonedx.model.ServiceData sd = new org.cyclonedx.model.ServiceData(dc.getDirection().name(), dc.getName());
                cycloneService.addServiceData(sd);
            }
        }
        if (service.getExternalReferences() != null && !service.getExternalReferences().isEmpty()) {
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
        if (vulnerability.getOwaspRRLikelihoodScore() != null && vulnerability.getOwaspRRTechnicalImpactScore() != null && vulnerability.getOwaspRRBusinessImpactScore() != null) {
            org.cyclonedx.model.vulnerability.Vulnerability.Rating rating = new org.cyclonedx.model.vulnerability.Vulnerability.Rating();
            rating.setSeverity(convertDtSeverityToCdxSeverity(VulnerabilityUtil.normalizedOwaspRRScore(vulnerability.getOwaspRRLikelihoodScore().doubleValue(), vulnerability.getOwaspRRTechnicalImpactScore().doubleValue(), vulnerability.getOwaspRRBusinessImpactScore().doubleValue())));
            rating.setSource(convertDtVulnSourceToCdxVulnSource(Vulnerability.Source.valueOf(vulnerability.getSource())));
            rating.setMethod(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method.OWASP);
            rating.setVector(vulnerability.getOwaspRRVector());
            cdxVulnerability.addRating(rating);
        }
        if (vulnerability.getCvssV2BaseScore() == null && vulnerability.getCvssV3BaseScore() == null && vulnerability.getOwaspRRLikelihoodScore() == null) {
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

        if (CycloneDXExporter.Variant.INVENTORY_WITH_VULNERABILITIES == variant || CycloneDXExporter.Variant.VDR == variant) {
            final List<org.cyclonedx.model.vulnerability.Vulnerability.Affect> affects = new ArrayList<>();
            final org.cyclonedx.model.vulnerability.Vulnerability.Affect affect = new org.cyclonedx.model.vulnerability.Vulnerability.Affect();
            affect.setRef(component.getUuid().toString());
            affects.add(affect);
            cdxVulnerability.setAffects(affects);
        } else if (CycloneDXExporter.Variant.VEX == variant && project != null) {
            final List<org.cyclonedx.model.vulnerability.Vulnerability.Affect> affects = new ArrayList<>();
            final org.cyclonedx.model.vulnerability.Vulnerability.Affect affect = new org.cyclonedx.model.vulnerability.Vulnerability.Affect();
            affect.setRef(project.getUuid().toString());
            affects.add(affect);
            cdxVulnerability.setAffects(affects);
        }

        if (CycloneDXExporter.Variant.VEX == variant || CycloneDXExporter.Variant.VDR == variant) {
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
        }

        return cdxVulnerability;
    }

    /**
     * Converts {@link Project#getDirectDependencies()} and {@link Component#getDirectDependencies()}
     * references to a CycloneDX dependency graph.
     *
     * @param project    The {@link Project} to generate the graph for
     * @param components The {@link Component}s belonging to {@code project}
     * @return The CycloneDX representation of the {@link Project}'s dependency graph
     */
    public static List<Dependency> generateDependencies(final Project project, final List<Component> components) {
        if (project == null) {
            return Collections.emptyList();
        }

        final var dependencies = new ArrayList<Dependency>();
        final var rootDependency = new Dependency(project.getUuid().toString());
        rootDependency.setDependencies(convertDirectDependencies(project.getDirectDependencies(), components));
        dependencies.add(rootDependency);

        for (final Component component : components) {
            final var dependency = new Dependency(component.getUuid().toString());
            dependency.setDependencies(convertDirectDependencies(component.getDirectDependencies(), components));
            dependencies.add(dependency);
        }

        return dependencies;
    }

    private static List<Dependency> convertDirectDependencies(final String directDependenciesRaw, final List<Component> components) {
        if (directDependenciesRaw == null || directDependenciesRaw.isBlank()) {
            return Collections.emptyList();
        }

        final var dependencies = new ArrayList<Dependency>();
        final JsonValue directDependenciesJson = Json
                .createReader(new StringReader(directDependenciesRaw))
                .readValue();
        if (directDependenciesJson instanceof final JsonArray directDependenciesJsonArray) {
            for (final JsonValue directDependency : directDependenciesJsonArray) {
                if (directDependency instanceof final JsonObject directDependencyObject) {
                    final String componentUuid = directDependencyObject.getString("uuid", null);
                    if (componentUuid != null && components.stream().map(Component::getUuid).map(UUID::toString).anyMatch(componentUuid::equals)) {
                        dependencies.add(new Dependency(directDependencyObject.getString("uuid")));
                    }
                }
            }
        }

        return dependencies;
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
