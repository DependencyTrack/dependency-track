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
import org.dependencytrack.event.PolicyEvaluationEvent;
import org.dependencytrack.event.RepositoryMetaEvent;
import org.dependencytrack.event.VulnerabilityAnalysisEvent;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.CompressUtil;
import org.dependencytrack.util.InternalComponentIdentificationUtil;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
    @Override
    public void inform(final Event e) {
        if (e instanceof BomUploadEvent) {
            Project bomProcessingFailedProject = null;
            Bom.Format bomProcessingFailedBomFormat = null;
            String bomProcessingFailedBomVersion = null;
            final BomUploadEvent event = (BomUploadEvent) e;
            final byte[] bomBytes = CompressUtil.optionallyDecompress(event.getBom());
            final QueryManager qm = new QueryManager();
            try {
                final Project project =  qm.getObjectByUuid(Project.class, event.getProjectUuid());
                bomProcessingFailedProject = project;

                if (project == null) {
                    LOGGER.warn("Ignoring BOM Upload event for no longer existing project " + event.getProjectUuid());
                    return;
                }

                final List<Component> components;
                final List<Component> newComponents = new ArrayList<>();
                final List<Component> flattenedComponents = new ArrayList<>();
                final List<ServiceComponent> services;
                final List<ServiceComponent> flattenedServices = new ArrayList<>();
                final List<Vulnerability> vulnerabilities;

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
                        bomProcessingFailedBomFormat = bomFormat;
                        final Parser parser = BomParserFactory.createParser(bomBytes);
                        cycloneDxBom = parser.parse(bomBytes);
                        bomSpecVersion = cycloneDxBom.getSpecVersion();
                        bomProcessingFailedBomVersion = bomSpecVersion;
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
                        project.setExternalReferences(ModelConverter.convertBomMetadataExternalReferences(cycloneDxBom));
                        serialNumnber = (cycloneDxBom.getSerialNumber() != null) ? cycloneDxBom.getSerialNumber().replaceFirst("urn:uuid:", "") : null;
                        components = ModelConverter.convertComponents(qm, cycloneDxBom, project);
                        services = ModelConverter.convertServices(qm, cycloneDxBom, project);
                        vulnerabilities = ModelConverter.convertVulnerabilities(cycloneDxBom, components, services);
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
                qm.createBom(project, date, bomFormat, bomSpecVersion, bomVersion, serialNumnber);
                for (final Component component: components) {
                    processComponent(qm, component, flattenedComponents, newComponents);
                }
                LOGGER.info("Identified " + newComponents.size() + " new components");
                for (final ServiceComponent service: services) {
                    processService(qm, service, flattenedServices);
                }
                if (Bom.Format.CYCLONEDX == bomFormat) {
                    LOGGER.info("Processing CycloneDX dependency graph for project: " + event.getProjectUuid());
                    ModelConverter.generateDependencies(cycloneDxBom, project, components);
                }
                LOGGER.debug("Reconciling components for project " + event.getProjectUuid());
                qm.reconcileComponents(project, existingProjectComponents, flattenedComponents);
                LOGGER.debug("Reconciling services for project " + event.getProjectUuid());
                qm.reconcileServiceComponents(project, existingProjectServices, flattenedServices);
                processVulnerabilities(qm, vulnerabilities, flattenedComponents, flattenedServices);
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
                // Start PolicyEvaluationEvent when VulnerabilityAnalysisEvent is succesful
                vae.onSuccess(new PolicyEvaluationEvent(detachedFlattenedComponent).project(detachedProject));
                Event.dispatch(vae);

                // Repository Metadata analysis
                final var rme = new RepositoryMetaEvent(detachedFlattenedComponent);
                // Start PolicyEvaluationEvent again when RepositoryMetaEvent is succesful,
                // as it might trigger new violations
                rme.onSuccess(new PolicyEvaluationEvent(detachedFlattenedComponent).project(detachedProject));
                Event.dispatch(rme);

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
                if (bomProcessingFailedProject != null) {
                    bomProcessingFailedProject = qm.detach(Project.class, bomProcessingFailedProject.getId());
                }
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.PORTFOLIO)
                        .group(NotificationGroup.BOM_PROCESSING_FAILED)
                        .title(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                        .level(NotificationLevel.ERROR)
                        .content("An error occurred while processing a BOM")
                        .subject(new BomProcessingFailed(bomProcessingFailedProject, Base64.getEncoder().encodeToString(bomBytes), ex.getMessage(), bomProcessingFailedBomFormat, bomProcessingFailedBomVersion)));
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
        if (component.getChildren() != null) {
            for (final Component child : component.getChildren()) {
                processComponent(qm, child, flattenedComponents, newComponents);
            }
        }
    }

    private void processService(final QueryManager qm, ServiceComponent service,
                                  final List<ServiceComponent> flattenedServices) {
        service = qm.createServiceComponent(service, false);
        final long oid = service.getId();
        // Refreshing the object by querying for it again is preventative
        flattenedServices.add(qm.getObjectById(ServiceComponent.class, oid));
        if (service.getChildren() != null) {
            for (final ServiceComponent child : service.getChildren()) {
                processService(qm, child, flattenedServices);
            }
        }
    }

    private List<Vulnerability> processVulnerabilities(final QueryManager qm, final List<Vulnerability> vulnerabilitiesTransient,
            final List<Component> componentsHollow, final List<ServiceComponent> servicesHollow) {
        filterUnknownCwes(qm, vulnerabilitiesTransient);

        class VulnerabilityPair {
            Vulnerability oldV;
            Vulnerability newV;
            VulnerabilityPair(Vulnerability o, Vulnerability n) {
                oldV = o; newV = n;
            }
        }
        Stream<VulnerabilityPair> stream = vulnerabilitiesTransient.stream()
                .map(v -> new VulnerabilityPair(qm.getVulnerabilityByVulnId(v.getSource(), v.getVulnId()), v));

        Map<ComponentIdentity, Component> newComponents = componentsHollow.stream().collect(Collectors.toMap(
                c -> new ComponentIdentity(c), c -> c));
        Map<ComponentIdentity, ServiceComponent> newServices = servicesHollow.stream().collect(Collectors.toMap(
                s -> new ComponentIdentity(s), s -> s));

        Stream<Vulnerability> mergedVulns = stream.map(pair -> {
            // Merge the transient vulnerability to the hollow one.
            final Vulnerability merged;
            final List<Component> mergedComponents = new ArrayList<Component>();
            final List<ServiceComponent> mergedServiceComponents = new ArrayList<ServiceComponent>();
            if (pair.oldV == null) {
                // No matching already persisted vulnerability found. Persist the transient one.
                merged = pair.newV;

                // Switch the possibly transient components and services to matching persisted ones.
                mergedComponents.addAll(Optional.ofNullable(merged.getComponents()).orElse(Collections.emptyList())
                        .stream().map(c -> newComponents.get(new ComponentIdentity(c))).filter(Objects::nonNull).toList());
                mergedServiceComponents.addAll(Optional.ofNullable(merged.getComponents()).orElse(Collections.emptyList())
                        .stream().map(s -> newServices.get(new ComponentIdentity(s))).filter(Objects::nonNull).toList());
            } else {
                merged = pair.oldV;
                Optional.ofNullable(pair.newV.getCreated()).ifPresent(value -> merged.setCreated(value));
                Optional.ofNullable(pair.newV.getPublished()).ifPresent(value -> merged.setPublished(value));
                Optional.ofNullable(pair.newV.getUpdated()).ifPresent(value -> merged.setUpdated(value));
                Optional.ofNullable(pair.newV.getVulnId()).ifPresent(value -> merged.setVulnId(value));
                Optional.ofNullable(pair.newV.getSource()).ifPresent(value -> merged.setSource(value));
                Optional.ofNullable(pair.newV.getCredits()).ifPresent(value -> merged.setCredits(value));
                Optional.ofNullable(pair.newV.getVulnerableVersions()).ifPresent(value -> merged.setVulnerableVersions(value));
                Optional.ofNullable(pair.newV.getPatchedVersions()).ifPresent(value -> merged.setPatchedVersions(value));
                Optional.ofNullable(pair.newV.getDescription()).ifPresent(value -> merged.setDescription(value));
                Optional.ofNullable(pair.newV.getDetail()).ifPresent(value -> merged.setDetail(value));
                Optional.ofNullable(pair.newV.getTitle()).ifPresent(value -> merged.setTitle(value));
                Optional.ofNullable(pair.newV.getSubTitle()).ifPresent(value -> merged.setSubTitle(value));
                Optional.ofNullable(pair.newV.getReferences()).ifPresent(value -> merged.setReferences(value));
                Optional.ofNullable(pair.newV.getRecommendation()).ifPresent(value -> merged.setRecommendation(value));
                Optional.ofNullable(pair.newV.getSeverity()).ifPresent(value -> merged.setSeverity(value));
                Optional.ofNullable(pair.newV.getCvssV2Vector()).ifPresent(value -> merged.setCvssV2Vector(value));
                Optional.ofNullable(pair.newV.getCvssV2BaseScore()).ifPresent(value -> merged.setCvssV2BaseScore(value));
                Optional.ofNullable(pair.newV.getCvssV2ImpactSubScore()).ifPresent(value -> merged.setCvssV2ImpactSubScore(value));
                Optional.ofNullable(pair.newV.getCvssV2ExploitabilitySubScore()).ifPresent(value -> merged.setCvssV2ExploitabilitySubScore(value));
                Optional.ofNullable(pair.newV.getCvssV3Vector()).ifPresent(value -> merged.setCvssV3Vector(value));
                Optional.ofNullable(pair.newV.getCvssV3BaseScore()).ifPresent(value -> merged.setCvssV3BaseScore(value));
                Optional.ofNullable(pair.newV.getCvssV3ImpactSubScore()).ifPresent(value -> merged.setCvssV3ImpactSubScore(value));
                Optional.ofNullable(pair.newV.getCvssV3ExploitabilitySubScore()).ifPresent(value -> merged.setCvssV3ExploitabilitySubScore(value));
                Optional.ofNullable(pair.newV.getOwaspRRLikelihoodScore()).ifPresent(value -> merged.setOwaspRRLikelihoodScore(value));
                Optional.ofNullable(pair.newV.getOwaspRRBusinessImpactScore()).ifPresent(value -> merged.setOwaspRRBusinessImpactScore(value));
                Optional.ofNullable(pair.newV.getOwaspRRTechnicalImpactScore()).ifPresent(value -> merged.setOwaspRRTechnicalImpactScore(value));
                Optional.ofNullable(pair.newV.getOwaspRRVector()).ifPresent(value -> merged.setOwaspRRVector(value));
                Optional.ofNullable(pair.newV.getCwes()).ifPresent(value -> merged.setCwes(value));

                {
                    final Map<ComponentIdentity, Component> existingComponents =
                            Optional.ofNullable(merged.getComponents()).orElse(Collections.emptyList())
                            .stream().collect(Collectors.toMap(c -> new ComponentIdentity(c), c -> c));
                    mergedComponents.addAll(existingComponents.values());
                    for (Component c : Optional.ofNullable(pair.newV.getComponents()).orElse(Collections.emptyList())) {
                        ComponentIdentity identity = new ComponentIdentity(c);
                        Component existingComponent = existingComponents.get(identity);
                        if (existingComponent != null) continue;
                        Component newComponent = newComponents.get(identity);
                        if (newComponent != null)
                            mergedComponents.add(newComponent);
                    }
                }

                {
                    final Map<ComponentIdentity, ServiceComponent> existingServices =
                            Optional.ofNullable(merged.getServiceComponents()).orElse(Collections.emptyList())
                            .stream().collect(Collectors.toMap(s -> new ComponentIdentity(s), s -> s));
                    mergedServiceComponents.addAll(existingServices.values());
                    for (ServiceComponent s : Optional.ofNullable(pair.newV.getServiceComponents()).orElse(Collections.emptyList())) {
                        ComponentIdentity identity = new ComponentIdentity(s);
                        ServiceComponent existingService = existingServices.get(identity);
                        if (existingService != null) continue;
                        ServiceComponent newService = newServices.get(identity);
                        if (newService != null)
                            mergedServiceComponents.add(newService);
                    }
                }

                // Merge Vulnerable Software.
                List<VulnerableSoftware> mergedVulnerableSoftwares = Stream.concat(
                        Optional.ofNullable(merged.getVulnerableSoftware()).orElse(Collections.emptyList()).stream(),
                        Optional.ofNullable(pair.newV.getVulnerableSoftware()).orElse(Collections.emptyList()).stream()).toList();
                if (!mergedVulnerableSoftwares.isEmpty()) merged.setVulnerableSoftware(mergedVulnerableSoftwares);
            }

            if (!mergedComponents.isEmpty()) merged.setComponents(mergedComponents);
            if (!mergedServiceComponents.isEmpty()) merged.setServiceComponents(mergedServiceComponents);

            return merged;
        });

        List<Vulnerability> mergedVulnerabilities = mergedVulns.toList();
        class SearchIndexInfo {
            Vulnerability vulnerability;
            IndexEvent.Action action;
            SearchIndexInfo(Vulnerability v, IndexEvent.Action a) {
                vulnerability = v; action = a;
            }
        }
        final List<SearchIndexInfo> searchIndexInfo = mergedVulnerabilities.stream().map(v -> new SearchIndexInfo(
                v, v.getUuid() == null ? IndexEvent.Action.CREATE : IndexEvent.Action.UPDATE )).toList();
        mergedVulnerabilities = qm.persist(mergedVulnerabilities).stream().map(o -> (Vulnerability)o).toList();
        for (SearchIndexInfo info : searchIndexInfo)
            Event.dispatch(new IndexEvent(info.action, qm.getPersistenceManager().detachCopy(info.vulnerability)));
        return mergedVulnerabilities;
    }

    private void filterUnknownCwes(final QueryManager qm, final List<Vulnerability> vulnerabilities) {
        // Get CWEs that were included in the vulnerabilities and have been persisted.
        // TODO: This could be faster if CWEs were fetched with a single query.
        final Stream<Integer> cwes = vulnerabilities.stream().map(v -> v.getCwes())
                .filter(Objects::nonNull).map(cs -> cs.stream())
                .reduce(Stream.empty(), (a, b) -> Stream.concat(a, b));
        final java.util.Set<Integer> existingCwes = cwes.map(cwe -> qm.getCweById(cwe))
                .filter(Objects::nonNull).map(cwe -> cwe.getCweId()).collect(Collectors.toUnmodifiableSet());

        // Filter out unknown CWEs from the vulnerabilities as is done in VulnerabilityResource
        for (final Vulnerability vulnerability : vulnerabilities) {
            final List<Integer> current = vulnerability.getCwes();
            if(current != null)
                vulnerability.setCwes(current.stream().filter(i -> existingCwes.contains(i)).toList());
        }
    }
}
