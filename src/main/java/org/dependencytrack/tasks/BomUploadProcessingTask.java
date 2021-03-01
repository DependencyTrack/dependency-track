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

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.cyclonedx.BomParserFactory;
import org.cyclonedx.parsers.Parser;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.event.RepositoryMetaEvent;
import org.dependencytrack.event.VulnerabilityAnalysisEvent;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.parser.spdx.rdf.SpdxDocumentParser;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.CompressUtil;
import org.dependencytrack.util.InternalComponentIdentificationUtil;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

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
                final List<Component> flattenedComponents = new ArrayList<>();
                final List<ServiceComponent> services;
                final List<ServiceComponent> flattenedServices = new ArrayList<>();

                // Holds a list of all Components that are existing dependencies of the specified project
                final List<Component> existingProjectComponents = qm.getAllComponents(project);
                final List<ServiceComponent> existingProjectServices = qm.getAllServiceComponents(project);
                final String bomString = new String(bomBytes, StandardCharsets.UTF_8);
                final Bom.Format bomFormat;
                final String bomSpecVersion;
                if (BomParserFactory.looksLikeCycloneDX(bomBytes)) {
                    if (qm.isEnabled(ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX)) {
                        LOGGER.info("Processing CycloneDX BOM uploaded to project: " + event.getProjectUuid());
                        bomFormat = Bom.Format.CYCLONEDX;
                        final Parser parser = BomParserFactory.createParser(bomBytes);
                        final org.cyclonedx.model.Bom bom = parser.parse(bomBytes);
                        bomSpecVersion = bom.getSpecVersion();
                        components = ModelConverter.convertComponents(qm, bom, project);
                        services = ModelConverter.convertServices(qm, bom, project);
                    } else {
                        LOGGER.warn("A CycloneDX BOM was uploaded but accepting CycloneDX BOMs is disabled. Aborting");
                        return;
                    }
                } else if (SpdxDocumentParser.isSupportedSpdxFormat(bomString)) {
                    if (qm.isEnabled(ConfigPropertyConstants.ACCEPT_ARTIFACT_SPDX)) {
                        LOGGER.info("Processing SPDX BOM uploaded to project: " + event.getProjectUuid());
                        bomFormat = Bom.Format.SPDX;
                        final SpdxDocumentParser parser = new SpdxDocumentParser(qm);
                        components = parser.parse(bomBytes, project);
                        services = new ArrayList<>(); // SPDX does not support services
                        bomSpecVersion = parser.getSpecVersion(); // Must come after the parsing is performed
                    } else {
                        LOGGER.warn("A SPDX BOM was uploaded but accepting SPDX BOMs is disabled. Aborting");
                        return;
                    }
                } else {
                    LOGGER.warn("The BOM uploaded is not in a supported format. Supported formats include CycloneDX, SPDX RDF, and SPDX Tag");
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
                final Bom bom = qm.createBom(project, date, bomFormat, bomSpecVersion);
                for (final Component component: components) {
                    processComponent(qm, bom, component, flattenedComponents);
                }
                for (final ServiceComponent service: services) {
                    processService(qm, bom, service, flattenedServices);
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

    private void processComponent(final QueryManager qm, final Bom bom, Component component,
                                  final List<Component> flattenedComponents) {
        component.setInternal(InternalComponentIdentificationUtil.isInternalComponent(component, qm));
        component = qm.createComponent(component, false);
        final long oid = component.getId();
        // Refreshing the object by querying for it again is preventative
        flattenedComponents.add(qm.getObjectById(Component.class, oid));
        Event.dispatch(new RepositoryMetaEvent(component));
        if (component.getChildren() != null) {
            for (final Component child : component.getChildren()) {
                processComponent(qm, bom, child, flattenedComponents);
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
