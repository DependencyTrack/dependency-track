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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.cyclonedx.BomParserFactory;
import org.cyclonedx.parsers.Parser;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.event.NewVulnerableDependencyAnalysisEvent;
import org.dependencytrack.event.RepositoryMetaEvent;
import org.dependencytrack.event.VulnerabilityAnalysisEvent;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.CompressUtil;
import org.dependencytrack.util.InternalComponentIdentificationUtil;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Subscriber task that performs processing of bill-of-material (bom)
 * when it is uploaded.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class BomUploadProcessingTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(BomUploadProcessingTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof BomUploadEvent) {
            final BomUploadEvent event = (BomUploadEvent) e;
            final byte[] bomBytes = CompressUtil.optionallyDecompress(event.getBom());
            final QueryManager qm = new QueryManager();
            try {
                final Project project = qm.getObjectByUuid(Project.class, event.getProjectUuid());
                final List<Component> components;
                final List<Component> newComponents = new ArrayList<>();
                final List<Component> flattenedComponents = new ArrayList<>();
                final List<ServiceComponent> services;
                final List<ServiceComponent> flattenedServices = new ArrayList<>();

                // Holds a list of all Components that are existing dependencies of the specified project
                final List<Component> existingProjectComponents = qm.getAllComponents(project);
                final List<ServiceComponent> existingProjectServices = qm.getAllServiceComponents(project);
                final Bom.Format bomFormat;
                final String bomSpecVersion;
                final Integer bomVersion;
                final String serialNumnber;
                org.cyclonedx.model.Bom cycloneDxBom = null;
                if (BomParserFactory.looksLikeCycloneDX(bomBytes)) {
                    if (qm.isEnabled(ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX)) {
                        LOGGER.info("Processing CycloneDX BOM uploaded to project: " + event.getProjectUuid());
                        bomFormat = Bom.Format.CYCLONEDX;
                        final Parser parser = BomParserFactory.createParser(bomBytes);
                        cycloneDxBom = parser.parse(bomBytes);
                        bomSpecVersion = cycloneDxBom.getSpecVersion();
                        bomVersion = cycloneDxBom.getVersion();
                        if (project.getClassifier() == null) {
                            final var classifier = Optional.ofNullable(cycloneDxBom.getMetadata())
                                .map(org.cyclonedx.model.Metadata::getComponent)
                                .map(org.cyclonedx.model.Component::getType)
                                .map(org.cyclonedx.model.Component.Type::name)
                                .map(Classifier::valueOf)
                                .orElse(Classifier.APPLICATION);
                            project.setClassifier(classifier);
                        }
                        serialNumnber = (cycloneDxBom.getSerialNumber() != null) ? cycloneDxBom.getSerialNumber().replaceFirst("urn:uuid:", "") : null;
                        components = ModelConverter.convertComponents(qm, cycloneDxBom, project);
                        services = ModelConverter.convertServices(qm, cycloneDxBom, project);
                    } else {
                        LOGGER.warn("A CycloneDX BOM was uploaded but accepting CycloneDX BOMs is disabled. Aborting");
                        return;
                    }
                } else {
                    LOGGER.warn("The BOM uploaded is not in a supported format. Supported formats include CycloneDX XML and JSON");
                    return;
                }
                final Project copyOfProject = qm.detach(Project.class, qm.getObjectById(Project.class, project.getId()).getId());
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.PORTFOLIO)
                        .group(NotificationGroup.BOM_CONSUMED)
                        .title(NotificationConstants.Title.BOM_CONSUMED)
                        .level(NotificationLevel.INFORMATIONAL)
                        .content("A " + bomFormat.getFormatShortName() + " BOM was consumed and will be processed")
                        .subject(new BomConsumedOrProcessed(copyOfProject, Base64.getEncoder().encodeToString(bomBytes), bomFormat, bomSpecVersion)));
                final Date date = new Date();
                final Bom bom = qm.createBom(project, date, bomFormat, bomSpecVersion, bomVersion, serialNumnber);
                for (final Component component: components) {
                    processComponent(qm, component, flattenedComponents, newComponents);
                }
                LOGGER.info("Identified " + newComponents.size() + " new components");
                for (final ServiceComponent service: services) {
                    processService(qm, bom, service, flattenedServices);
                }
                if (Bom.Format.CYCLONEDX == bomFormat) {
                    LOGGER.info("Processing CycloneDX dependency graph for project: " + event.getProjectUuid());
                    ModelConverter.generateDependencies(qm, cycloneDxBom, project, components);
                }
                LOGGER.debug("Reconciling components for project " + event.getProjectUuid());
                qm.reconcileComponents(project, existingProjectComponents, flattenedComponents);
                LOGGER.debug("Reconciling services for project " + event.getProjectUuid());
                qm.reconcileServiceComponents(project, existingProjectServices, flattenedServices);
                LOGGER.debug("Updating last import date for project " + event.getProjectUuid());
                qm.updateLastBomImport(project, date, bomFormat.getFormatShortName() + " " + bomSpecVersion);
                // Instead of firing off a new VulnerabilityAnalysisEvent, chain the VulnerabilityAnalysisEvent to
                // the BomUploadEvent so that synchronous publishing mode (Jenkins) waits until vulnerability
                // analysis has completed. If not chained, synchronous publishing mode will return immediately upon
                // return from this method, resulting in inaccurate findings being returned in the response (since
                // the vulnerability analysis hasn't taken place yet).
                final List<Component> detachedFlattenedComponent = qm.detach(flattenedComponents);
                final Project detachedProject = qm.detach(Project.class, project.getId());
                final VulnerabilityAnalysisEvent vae = new VulnerabilityAnalysisEvent(detachedFlattenedComponent).project(detachedProject);
                vae.setChainIdentifier(event.getChainIdentifier());
                if (!newComponents.isEmpty()) {
                    // Whether a new dependency is vulnerable or not can only be determined after
                    // vulnerability analysis completed.
                    vae.onSuccess(new NewVulnerableDependencyAnalysisEvent(newComponents));
                }
                Event.dispatch(vae);
                LOGGER.info("Processed " + flattenedComponents.size() + " components and " + flattenedServices.size() + " services uploaded to project " + event.getProjectUuid());
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.PORTFOLIO)
                        .group(NotificationGroup.BOM_PROCESSED)
                        .title(NotificationConstants.Title.BOM_PROCESSED)
                        .level(NotificationLevel.INFORMATIONAL)
                        .content("A " + bomFormat.getFormatShortName() + " BOM was processed")
                        .subject(new BomConsumedOrProcessed(detachedProject, Base64.getEncoder().encodeToString(bomBytes), bomFormat, bomSpecVersion)));
            } catch (Exception ex) {
                LOGGER.error("Error while processing bom", ex);
            } finally {
                qm.commitSearchIndex(true, Component.class);
                qm.commitSearchIndex(true, ServiceComponent.class);
                qm.close();
            }
        }
    }

    private void processComponent(final QueryManager qm, Component component,
                                  final List<Component> flattenedComponents,
                                  final List<Component> newComponents) {
        final boolean isNew = component.getUuid() == null;
        component.setInternal(InternalComponentIdentificationUtil.isInternalComponent(component, qm));
        component = qm.createComponent(component, false);
        final long oid = component.getId();
        // Refreshing the object by querying for it again is preventative
        component = qm.getObjectById(Component.class, oid);
        flattenedComponents.add(component);
        if (isNew) {
            newComponents.add(qm.detach(Component.class, component.getId()));
        }
        Event.dispatch(new RepositoryMetaEvent(component));
        if (component.getChildren() != null) {
            for (final Component child : component.getChildren()) {
                processComponent(qm, child, flattenedComponents, newComponents);
            }
        }
    }

    private void processService(final QueryManager qm, final Bom bom, ServiceComponent service,
                                  final List<ServiceComponent> flattenedServices) {
        service = qm.createServiceComponent(service, false);
        final long oid = service.getId();
        // Refreshing the object by querying for it again is preventative
        flattenedServices.add(qm.getObjectById(ServiceComponent.class, oid));
        if (service.getChildren() != null) {
            for (final ServiceComponent child : service.getChildren()) {
                processService(qm, bom, child, flattenedServices);
            }
        }
    }
}
