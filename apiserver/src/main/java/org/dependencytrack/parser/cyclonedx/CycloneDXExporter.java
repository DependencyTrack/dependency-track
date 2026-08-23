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
import org.dependencytrack.persistence.jdbi.FindingDao;

import javax.jdo.FetchGroup;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class CycloneDXExporter {

    public enum Format {
        JSON,
        XML
    }

    public enum Capability {
        EMITS_COMPONENTS,
        EMITS_DEPENDENCY_GRAPH,
        EMITS_FINDINGS,
        EMITS_SERVICES,
        FILTERS_TO_VULNERABLE_COMPONENTS
    }

    public enum Variant {

        INVENTORY(
                Capability.EMITS_COMPONENTS,
                Capability.EMITS_SERVICES,
                Capability.EMITS_DEPENDENCY_GRAPH),
        INVENTORY_WITH_VULNERABILITIES(
                Capability.EMITS_FINDINGS,
                Capability.EMITS_COMPONENTS,
                Capability.EMITS_SERVICES,
                Capability.EMITS_DEPENDENCY_GRAPH),
        VDR(
                Capability.FILTERS_TO_VULNERABLE_COMPONENTS,
                Capability.EMITS_FINDINGS,
                Capability.EMITS_COMPONENTS,
                Capability.EMITS_SERVICES,
                Capability.EMITS_DEPENDENCY_GRAPH),
        VEX(
                Capability.EMITS_FINDINGS);

        private final Set<Capability> capabilities;

        Variant(Capability... capabilities) {
            final Set<Capability> set = EnumSet.noneOf(Capability.class);
            set.addAll(List.of(capabilities));
            this.capabilities = set;
        }

        public boolean hasCapability(Capability capability) {
            return capabilities.contains(capability);
        }

    }

    private final QueryManager qm;
    private final Variant variant;

    public CycloneDXExporter(final Variant variant, final QueryManager qm) {
        this.variant = variant;
        this.qm = qm;
    }

    public Bom create(final Project project, final Version version) {
        final List<Component> components;
        final List<ServiceComponent> services;
        try (var _ = new ScopedCustomization(qm.getPersistenceManager())
                .withFetchGroup(FetchGroup.ALL)) {
            components = qm.getAllComponents(project);
            services = qm.getAllServiceComponents(project);
        }
        final List<Finding> findings = variant.hasCapability(Capability.EMITS_FINDINGS)
                ? withJdbiHandle(handle -> handle.attach(FindingDao.class).getFindings(project.getId(), true))
                : null;
        return create(components, services, findings, project, version);
    }

    public Bom create(final Component component, final Version version) {
        final List<Component> components = new ArrayList<>();
        components.add(component);
        return create(components, null, null, null, version);
    }

    private Bom create(
            List<Component> components,
            final List<ServiceComponent> services,
            final List<Finding> findings,
            final Project project,
            final Version version) {
        if (variant.hasCapability(Capability.FILTERS_TO_VULNERABLE_COMPONENTS)) {
            final Set<UUID> vulnerableComponentUuids = findings.stream()
                    .map(finding -> (UUID) finding.getComponent().get("uuid"))
                    .collect(Collectors.toSet());
            components = components.stream()
                    .filter(component -> vulnerableComponentUuids.contains(component.getUuid()))
                    .toList();
        }
        final List<org.cyclonedx.model.Component> cycloneComponents =
                (variant.hasCapability(Capability.EMITS_COMPONENTS) && components != null)
                        ? components.stream().map(ModelConverter::convert).collect(Collectors.toList())
                        : null;
        final List<org.cyclonedx.model.Service> cycloneServices =
                (variant.hasCapability(Capability.EMITS_SERVICES) && services != null)
                        ? services.stream().map(service -> ModelConverter.convert(qm, service)).collect(Collectors.toList())
                        : null;
        final Bom bom = new Bom();
        bom.setSerialNumber("urn:uuid:" + UUID.randomUUID());
        bom.setVersion(1);
        bom.setMetadata(ModelConverter.createMetadata(project, version));
        bom.setComponents(cycloneComponents);
        bom.setServices(cycloneServices);
        bom.setVulnerabilities(ModelConverter.generateVulnerabilities(qm, variant, findings));
        if (variant.hasCapability(Capability.EMITS_DEPENDENCY_GRAPH) && cycloneComponents != null) {
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
