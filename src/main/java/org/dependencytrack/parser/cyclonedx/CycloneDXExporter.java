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
package org.dependencytrack.parser.cyclonedx;

import alpine.persistence.ScopedCustomization;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.FetchGroup;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class CycloneDXExporter {

    public enum Format {
        JSON,
        XML
    }

    public enum Variant {
        INVENTORY,
        INVENTORY_WITH_VULNERABILITIES,
        VDR,
        VEX
    }

    private final QueryManager qm;
    private final CycloneDXExporter.Variant variant;

    public CycloneDXExporter(final CycloneDXExporter.Variant variant, final QueryManager qm) {
        this.variant = variant;
        this.qm = qm;
    }

    public Bom create(final Project project) {
        final List<Component> components;
        final List<ServiceComponent> services;
        try (final var ignored = new ScopedCustomization(qm.getPersistenceManager())
                .withFetchGroup(FetchGroup.ALL)) {
            components = qm.getAllComponents(project);
            services = qm.getAllServiceComponents(project);
        }
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
        final Bom bom = new Bom();
        bom.setSerialNumber("urn:uuid:" + UUID.randomUUID());
        bom.setVersion(1);
        bom.setMetadata(ModelConverter.createMetadata(project));
        bom.setComponents(cycloneComponents);
        bom.setServices(cycloneServices);
        bom.setVulnerabilities(ModelConverter.generateVulnerabilities(qm, variant, findings));
        if (cycloneComponents != null) {
            bom.setDependencies(ModelConverter.generateDependencies(project, components));
        }
        return bom;
    }

    public String export(final Bom bom, final Format format, final Version version) throws GeneratorException {
        if (Format.JSON == format) {
            return BomGeneratorFactory.createJson(version, bom).toJsonString();
        }
        return BomGeneratorFactory.createXml(version, bom).toXmlString();
    }

}
