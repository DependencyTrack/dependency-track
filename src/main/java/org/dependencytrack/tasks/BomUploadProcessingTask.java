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
import org.cyclonedx.BomParser;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.event.RepositoryMetaEvent;
import org.dependencytrack.event.VulnerabilityAnalysisEvent;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.parser.dependencycheck.resolver.ComponentResolver;
import org.dependencytrack.parser.spdx.rdf.SpdxDocumentParser;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.CompressUtil;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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

                // Holds a list of all Components that are existing dependencies of the specified project
                final List<Component> existingProjectDependencies = new ArrayList<>();
                qm.getAllDependencies(project).forEach(item -> existingProjectDependencies.add(item.getComponent()));

                final String bomString = new String(bomBytes, StandardCharsets.UTF_8);
                if (bomString.startsWith("<?xml") && bomString.contains("<bom") && bomString.contains("http://cyclonedx.org/schema/bom")) {
                    if (qm.isEnabled(ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX)) {
                        LOGGER.info("Processing CycloneDX BOM uploaded to project: " + event.getProjectUuid());
                        final BomParser parser = new BomParser();
                        components = ModelConverter.convert(qm, parser.parse(bomBytes));
                    } else {
                        LOGGER.warn("A CycloneDX BOM was uploaded but accepting CycloneDX BOMs is disabled. Aborting");
                        return;
                    }
                } else if (SpdxDocumentParser.isSupportedSpdxFormat(bomString)) {
                    if (qm.isEnabled(ConfigPropertyConstants.ACCEPT_ARTIFACT_SPDX)) {
                        LOGGER.info("Processing SPDX BOM uploaded to project: " + event.getProjectUuid());
                        final SpdxDocumentParser parser = new SpdxDocumentParser(qm);
                        components = parser.parse(bomBytes);
                    } else {
                        LOGGER.warn("A SPDX BOM was uploaded but accepting SPDX BOMs is disabled. Aborting");
                        return;
                    }
                } else {
                    LOGGER.warn("The BOM uploaded is not in a supported format. Supported formats include CycloneDX, SPDX RDF, and SPDX Tag");
                    return;
                }
                final Date date = new Date();
                final Bom bom = qm.createBom(project, date);
                for (final Component component: components) {
                    processComponent(qm, bom, project, component, flattenedComponents);
                }
                LOGGER.debug("Reconciling dependencies for project " + event.getProjectUuid());
                qm.reconcileDependencies(project, existingProjectDependencies, flattenedComponents);
                LOGGER.debug("Updating last import date for project " + event.getProjectUuid());
                qm.updateLastBomImport(project, date);
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
                LOGGER.info("Processed " + flattenedComponents.size() + " components uploaded to project " + event.getProjectUuid());
            } catch (Exception ex) {
                LOGGER.error("Error while processing bom", ex);
            } finally {
                qm.commitSearchIndex(true, Component.class);
                qm.close();
            }
        }
    }

    private void processComponent(final QueryManager qm, final Bom bom, final Project project, Component component,
                                  final List<Component> flattenedComponents) {
        LOGGER.debug("Processing component (group:" + component.getGroup()
                + ", name:" + component.getName()
                + ", version:" + component.getVersion()
                + ", purl:" +  component.getPurl()
                + ") for project: " + project.getUuid().toString());
        final ComponentResolver cr = new ComponentResolver(qm);
        final Component resolvedComponent = cr.resolve(component);
        if (resolvedComponent != null) {
            LOGGER.debug("Component (group:" + component.getGroup()
                    + ", name:" + component.getName()
                    + ", version:" + component.getVersion()
                    + ", purl:" +  component.getPurl()
                    + ") has been resolved");
            final long oid = resolvedComponent.getId();
            resolvedComponent.setName(component.getName());
            resolvedComponent.setGroup(component.getGroup());
            resolvedComponent.setVersion(component.getVersion());
            resolvedComponent.setMd5(component.getMd5());
            resolvedComponent.setSha1(component.getSha1());
            resolvedComponent.setSha256(component.getSha256());
            resolvedComponent.setSha512(component.getSha512());
            resolvedComponent.setSha3_256(component.getSha3_256());
            resolvedComponent.setSha3_512(component.getSha3_512());
            resolvedComponent.setPurl(component.getPurl());
            resolvedComponent.setClassifier(component.getClassifier());
            resolvedComponent.setDescription(component.getDescription());
            resolvedComponent.setFilename(component.getFilename());
            resolvedComponent.setExtension(component.getExtension());
            resolvedComponent.setLicense(component.getLicense());
            resolvedComponent.setResolvedLicense(component.getResolvedLicense());
            qm.persist(resolvedComponent);
            bind(qm, project, resolvedComponent);
            qm.bind(bom, resolvedComponent);
            // IMPORTANT: refreshing the object by querying for it again is critical.
            flattenedComponents.add(qm.getObjectById(Component.class, oid));
        } else {
            LOGGER.debug("Component (group:" + component.getGroup()
                    + ", name:" + component.getName()
                    + ", version:" + component.getVersion()
                    + ", purl:" +  component.getPurl()
                    + ") is not resolved. Creating new component");
            component = qm.createComponent(component, false);

            final long oid = component.getId();
            bind(qm, project, component);
            qm.bind(bom, component);
            // Refreshing the object by querying for it again is preventative
            flattenedComponents.add(qm.getObjectById(Component.class, oid));
            Event.dispatch(new RepositoryMetaEvent(component));
        }
        if (component.getChildren() != null) {
            for (final Component child: component.getChildren()) {
                processComponent(qm, bom, project, child, flattenedComponents);
            }
        }
    }

    /**
     * Recursively bind component and all children to a project.
     */
    private void bind(final QueryManager qm, final Project project, final Component component) {
        qm.createDependencyIfNotExist(project, component, null, null);
        if (component.getChildren() != null) {
            for (final Component c: component.getChildren()) {
                bind(qm, project, c);
            }
        }
    }

}
