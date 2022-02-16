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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.QueryManager;
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
        VEX
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
        final List<Finding> findings = (Variant.INVENTORY_WITH_VULNERABILITIES == variant || Variant.VEX == variant) ? qm.getFindings(project, true) : null;
        return create(components, services, findings, project);
    }

    public Bom create(final Component component) {
        final List<Component> components = new ArrayList<>();
        components.add(component);
        return create(components, null, null, null);
    }

    private Bom create(final List<Component>components, final List<ServiceComponent> services, final List<Finding> findings, final Project project) {
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
        if (components != null) ModelConverter.generateDependencies(qm, bom, project, components);
        return bom;
    }

    public String export(final Bom bom, final Format format) throws GeneratorException {
        if (Format.JSON == format) {
            return BomGeneratorFactory.createJson(CycloneDxSchema.VERSION_LATEST, bom).toJsonString();
        } else {
            return BomGeneratorFactory.createXml(CycloneDxSchema.VERSION_LATEST, bom).toXmlString();
        }
    }

}
