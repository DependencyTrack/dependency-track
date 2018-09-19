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
package org.dependencytrack.parser.cyclonedx.util;

import alpine.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.cyclonedx.model.Hash;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.QueryManager;
import java.util.ArrayList;
import java.util.Collection;
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
    public static List<Component> convert(QueryManager qm, Bom bom) {
        final List<Component> components = new ArrayList<>();
        for (int i = 0; i < bom.getComponents().size(); i++) {
            components.add(convert(qm, bom.getComponents().get(i)));
        }
        return components;
    }

    public static Component convert(QueryManager qm, org.cyclonedx.model.Component cycloneDxComponent) {
        final Component component = new Component();
        component.setGroup(StringUtils.trimToNull(cycloneDxComponent.getGroup()));
        component.setName(StringUtils.trimToNull(cycloneDxComponent.getName()));
        component.setVersion(StringUtils.trimToNull(cycloneDxComponent.getVersion()));
        component.setDescription(StringUtils.trimToNull(cycloneDxComponent.getDescription()));
        component.setCopyright(StringUtils.trimToNull(cycloneDxComponent.getCopyright()));
        component.setCpe(StringUtils.trimToNull(cycloneDxComponent.getCpe()));

        try {
            component.setPurl(new PackageURL(cycloneDxComponent.getPurl()));
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Unable to parse PackageURL: " + cycloneDxComponent.getPurl());
        }

        final String type = StringUtils.trimToNull(cycloneDxComponent.getType());
        if ("application".toUpperCase().equals(type.toUpperCase())) {
            component.setClassifier(Classifier.APPLICATION);
        } else if ("framework".toUpperCase().equals(type.toUpperCase())) {
            component.setClassifier(Classifier.FRAMEWORK);
        } else if ("library".toUpperCase().equals(type.toUpperCase())) {
            component.setClassifier(Classifier.LIBRARY);
        } else if ("operating-system".toUpperCase().equals(type.toUpperCase())) {
            component.setClassifier(Classifier.OPERATING_SYSTEM);
        } else if ("device".toUpperCase().equals(type.toUpperCase())) {
            component.setClassifier(Classifier.DEVICE);
        }

        if (cycloneDxComponent.getHashes() != null && cycloneDxComponent.getHashes().size() > 0) {
            for (Hash hash : cycloneDxComponent.getHashes()) {
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

        if (cycloneDxComponent.getLicenses() != null && cycloneDxComponent.getLicenses().size() > 0) {
            for (org.cyclonedx.model.License cycloneLicense : cycloneDxComponent.getLicenses()) {
                if (StringUtils.isNotBlank(cycloneLicense.getId())) {
                    License license = qm.getLicense(StringUtils.trimToNull(cycloneLicense.getId()));
                    if (license != null) {
                        component.setResolvedLicense(license);
                    }
                }
                component.setLicense(StringUtils.trimToNull(cycloneLicense.getName()));
            }
        }

        if (cycloneDxComponent.getComponents() != null && cycloneDxComponent.getComponents().size() > 0) {
            final Collection<Component> components = new ArrayList<>();
            for (int i = 0; i < cycloneDxComponent.getComponents().size(); i++) {
                components.add(convert(qm, cycloneDxComponent.getComponents().get(i)));
            }
            if (components.size() > 0) {
                component.setChildren(components);
            }
        }
        return component;
    }

    public static org.cyclonedx.model.Component convert(QueryManager qm, Component component) {
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

        String type = "library";
        if (component.getClassifier() != null) {
            if (component.getClassifier() != null) {
                if (component.getClassifier() == Classifier.APPLICATION) {
                    type = "application";
                } else if (component.getClassifier() == Classifier.FRAMEWORK) {
                    type = "framework";
                } else if (component.getClassifier() == Classifier.LIBRARY) {
                    type = "library";
                } else if (component.getClassifier() == Classifier.OPERATING_SYSTEM) {
                    type = "operating-system";
                } else if (component.getClassifier() == Classifier.DEVICE) {
                    type = "device";
                }
            }
        }
        cycloneComponent.setType(type);

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
            org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setId(component.getResolvedLicense().getLicenseId());
            cycloneComponent.addLicense(license);
        } else if (component.getLicense() != null) {
            org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setName(component.getLicense());
            cycloneComponent.addLicense(license);
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
