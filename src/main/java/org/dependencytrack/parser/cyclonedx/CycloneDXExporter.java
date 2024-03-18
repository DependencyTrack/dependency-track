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
package org.dependencytrack.parser.cyclonedx;

import org.cyclonedx.BomGeneratorFactory;
import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.License;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.QueryManager;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.stream.Collectors;

public class CycloneDXExporter {

    public enum Format {
        JSON,
        XML,
        TEXT
    }

    public enum Variant {
        INVENTORY,
        INVENTORY_WITH_VULNERABILITIES,
        VDR,
        VEX,
        LICENSE_ATTESTATION
    }

    private final QueryManager qm;
    private final CycloneDXExporter.Variant variant;

    public CycloneDXExporter(final CycloneDXExporter.Variant variant, final QueryManager qm) {
        this.variant = variant;
        this.qm = qm;
    }

    public Bom create(final Project project) {
        final List<Component> components = qm.getAllComponents(project);
        final List<ServiceComponent> services = qm.getAllServiceComponents(project);
        final List<Finding> findings = switch (variant) {
            case INVENTORY_WITH_VULNERABILITIES, VDR, VEX -> qm.getFindings(project, true);
            default -> null;
        };
        return create(components, services, findings, project);
    }

    public Bom create(final Component component) {
        final List<Component> components = new ArrayList<>();
        components.add(component);
        return create(components, null, null, null);
    }

    private Bom create(List<Component> components, final List<ServiceComponent> services, final List<Finding> findings, final Project project) {
        if (Variant.VDR == variant) {
            components = components.stream()
                    .filter(component -> !component.getVulnerabilities().isEmpty())
                    .toList();
        }
        final List<org.cyclonedx.model.Component> cycloneComponents = (Variant.VEX != variant && components != null) ? components.stream().map(component -> ModelConverter.convert(qm, component)).collect(Collectors.toList()) : null;
        final List<org.cyclonedx.model.Service> cycloneServices = (Variant.VEX != variant && services != null) ? services.stream().map(service -> ModelConverter.convert(qm, service)).collect(Collectors.toList()) : null;
        final List<org.cyclonedx.model.vulnerability.Vulnerability> cycloneVulnerabilities = (findings != null) ? findings.stream().map(finding -> ModelConverter.convert(qm, variant, finding)).collect(Collectors.toList()) : null;
        final Bom bom = new Bom();
        bom.setSerialNumber("urn:uuid:" + UUID.randomUUID());
        bom.setVersion(1);
        bom.setMetadata(ModelConverter.createMetadata(project));
        bom.setComponents(cycloneComponents);
        bom.setServices(cycloneServices);
        bom.setVulnerabilities(cycloneVulnerabilities);
        if (cycloneComponents != null) {
            bom.setDependencies(ModelConverter.generateDependencies(project, components));
        }
        return bom;
    }

    public String export(final Bom bom, final Format format) throws GeneratorException {
        return switch (format) {
            case JSON -> BomGeneratorFactory.createJson(CycloneDxSchema.VERSION_LATEST, bom).toJsonString();
            case TEXT -> createText(bom);
            case XML -> BomGeneratorFactory.createXml(CycloneDxSchema.VERSION_LATEST, bom).toXmlString();
        };
    }

    private String createText(final Bom bom) {
        Map<org.dependencytrack.model.License, List<org.cyclonedx.model.Component>> componentToLicense = new TreeMap<>(Comparator.comparing(org.dependencytrack.model.License::getName));

        StringBuilder licenseText = new StringBuilder("Components:\n\n");
        List<org.cyclonedx.model.Component> bomComponents = bom.getComponents();
        bomComponents.sort(Comparator.comparing(org.cyclonedx.model.Component::getName));
        for (org.cyclonedx.model.Component component : bomComponents) {
            String name = component.getName();
            String version = component.getVersion();

            if (component.getLicenseChoice() == null) {
                continue;
            }
            List<License> licenses = component.getLicenseChoice().getLicenses();
            StringBuilder builder = new StringBuilder();
            if (licenses.size() > 1) {
                builder.append('(');
            }
            Iterator<License> iterator = licenses.iterator();
            while (iterator.hasNext()) {
                License lic = iterator.next();

                org.dependencytrack.model.License l = qm.getLicense(lic.getId());
                if (l == null) {
                    continue;
                }

                List<org.cyclonedx.model.Component> componentsForLicense = componentToLicense.get(l);
                if (componentsForLicense == null) {
                    componentsForLicense = new ArrayList<>();
                    componentsForLicense.add(component);
                    componentToLicense.put(l, componentsForLicense);
                } else {
                    componentsForLicense.add(component);
                }

                builder.append(l.getName());
                if (iterator.hasNext()) {
                    builder.append(" OR ");
                }
            }
            if (licenses.size() > 1) {
                builder.append(')');
            }

            licenseText.append(name).append(' ').append(version).append(" : ").append(builder).append('\n');
        }

        licenseText.append("\nLicenses:\n\n");

        // Generate license text with components
        licenseText.append(componentToLicense.entrySet().stream().map(licenseListEntry -> {
            org.dependencytrack.model.License l = licenseListEntry.getKey();
            List<org.cyclonedx.model.Component> components = licenseListEntry.getValue();

            return l.getName() + "\n"+
                    components.stream().map(c -> c.getName() + " " + c.getVersion()).collect(Collectors.joining(", ", "(", ")"))+
                    "\n\n"+ l.getText();
        }).collect(Collectors.joining("\n\n---\n\n")));

        return licenseText.toString();
    }

}
