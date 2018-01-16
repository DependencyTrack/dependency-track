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
package org.owasp.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import org.owasp.dependencytrack.event.BomUploadEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.parser.cyclonedx.CycloneDxParser;
import org.owasp.dependencytrack.parser.dependencycheck.resolver.ComponentResolver;
import org.owasp.dependencytrack.parser.spdx.rdf.SpdxDocumentParser;
import org.owasp.dependencytrack.persistence.QueryManager;
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
    public void inform(Event e) {
        if (e instanceof BomUploadEvent) {
            final BomUploadEvent event = (BomUploadEvent) e;
            final byte[] bomBytes = event.getBom();
            QueryManager qm = new QueryManager();
            try {
                final List<Component> components;
                final String bomString = new String(bomBytes);
                if (bomString.startsWith("<?xml") && bomString.contains("<bom") && bomString.contains("http://cyclonedx.org/schema/bom")) {
                    final CycloneDxParser parser = new CycloneDxParser(qm);
                    components = parser.convert(parser.parse(bomBytes));
                } else {
                    final SpdxDocumentParser parser = new SpdxDocumentParser(qm);
                    components = parser.parse(bomBytes);
                }
                final Project project = qm.getObjectByUuid(Project.class, event.getProjectUuid());
                for (Component component: components) {
                    processComponent(qm, project, component);
                }
            } catch (Exception ex) {
                LOGGER.error("Error while processing bom");
                LOGGER.error(ex.getMessage());
            } finally {
                qm.commitSearchIndex(true, Component.class);
                qm.close();
            }
        }
    }

    private void processComponent(QueryManager qm, Project project, Component component) {
        final ComponentResolver cr = new ComponentResolver(qm);
        final Component resolvedComponent = cr.resolve(component);
        if (resolvedComponent != null) {
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
        } else {
            component = qm.createComponent(component, false);
            bind(qm, project, component);
        }
        if (component.getChildren() != null) {
            for (Component child: component.getChildren()) {
                processComponent(qm, project, child);
            }
        }
    }

    /**
     * Recursively bind component and all children to a project.
     */
    private void bind(QueryManager qm, Project project, Component component) {
        qm.createDependencyIfNotExist(project, component, null, null);
        if (component.getChildren() != null) {
            for (Component c: component.getChildren()) {
                bind(qm, project, c);
            }
        }
    }

}
