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

import alpine.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.LicenseChoice;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.cyclonedx.model.Hash;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.InternalComponentIdentificationUtil;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

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
    public static List<Component> convert(final QueryManager qm, final Bom bom) {
        final List<Component> components = new ArrayList<>();
        for (int i = 0; i < bom.getComponents().size(); i++) {
            final org.cyclonedx.model.Component cycloneDxComponent = bom.getComponents().get(i);
            if (cycloneDxComponent != null) {
                components.add(convert(qm, cycloneDxComponent));
            }
        }
        return components;
    }

    public static Component convert(final QueryManager qm, final org.cyclonedx.model.Component cycloneDxComponent) {
        final Component component = new Component();
        component.setGroup(StringUtils.trimToNull(cycloneDxComponent.getGroup()));
        component.setName(StringUtils.trimToNull(cycloneDxComponent.getName()));
        component.setVersion(StringUtils.trimToNull(cycloneDxComponent.getVersion()));
        component.setDescription(StringUtils.trimToNull(cycloneDxComponent.getDescription()));
        component.setCopyright(StringUtils.trimToNull(cycloneDxComponent.getCopyright()));
        component.setCpe(StringUtils.trimToNull(cycloneDxComponent.getCpe()));

        if (StringUtils.isNotBlank(cycloneDxComponent.getPurl())) {
            try {
                component.setPurl(new PackageURL(StringUtils.trimToNull(cycloneDxComponent.getPurl())));
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

        if (cycloneDxComponent.getComponents() != null && !cycloneDxComponent.getComponents().isEmpty()) {
            final Collection<Component> components = new ArrayList<>();
            for (int i = 0; i < cycloneDxComponent.getComponents().size(); i++) {
                final org.cyclonedx.model.Component cycloneDxChildComponent = cycloneDxComponent.getComponents().get(i);
                if (cycloneDxChildComponent != null) {
                    components.add(convert(qm, cycloneDxChildComponent));
                }
            }
            if (CollectionUtils.isNotEmpty(components)) {
                component.setChildren(components);
            }
        }
        return component;
    }

    public static org.cyclonedx.model.Component convert(final QueryManager qm, final Component component) {
        final org.cyclonedx.model.Component cycloneComponent = new org.cyclonedx.model.Component();
        cycloneComponent.setGroup(StringUtils.trimToNull(component.getGroup()));
        cycloneComponent.setName(StringUtils.trimToNull(component.getName()));
        cycloneComponent.setVersion(StringUtils.trimToNull(component.getVersion()));
        cycloneComponent.setDescription(StringUtils.trimToNull(component.getDescription()));
        cycloneComponent.setCopyright(StringUtils.trimToNull(component.getCopyright()));
        cycloneComponent.setCpe(StringUtils.trimToNull(component.getCpe()));

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
}
