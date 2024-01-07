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
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.cyclonedx.BomParserFactory;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.Parser;
import org.datanucleus.flush.FlushMode;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.NewVulnerableDependencyAnalysisEvent;
import org.dependencytrack.event.PolicyEvaluationEvent;
import org.dependencytrack.event.RepositoryMetaEvent;
import org.dependencytrack.event.VulnerabilityAnalysisEvent;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.License;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisComment;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.json.JSONArray;
import org.slf4j.MDC;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;

import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.trim;
import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.datanucleus.PropertyNames.PROPERTY_FLUSH_MODE;
import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.datanucleus.PropertyNames.PROPERTY_RETAIN_VALUES;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertComponents;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertDependencyGraph;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertServices;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertToProject;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.flatten;
import static org.dependencytrack.util.PersistenceUtil.applyIfChanged;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

public class BomUploadProcessingTaskX implements Subscriber {

    private static final class Context {

        private final UUID token;
        private final Project project;
        private final String bomEncoded;
        private final Bom.Format bomFormat;
        private String bomSpecVersion;
        private String bomSerialNumber;
        private Integer bomVersion;

        private Context(final UUID token, final Project project, final byte[] bomBytes) {
            this.token = token;
            this.project = project;
            this.bomEncoded = Base64.getEncoder().encodeToString(bomBytes);
            this.bomFormat = Bom.Format.CYCLONEDX;
        }

    }

    private static final Logger LOGGER = Logger.getLogger(BomUploadProcessingTaskX.class);

    /**
     * {@link Event}s to dispatch <em>after</em> BOM processing completed successfully.
     * <p>
     * May include search index updates, or triggers for tasks relying on successful completion.
     */
    private final List<Event> eventsToDispatch = new ArrayList<>();

    @Override
    public void inform(final Event e) {
        if (!(e instanceof final BomUploadEvent event)) {
            return;
        }

        final var ctx = new Context(event.getChainIdentifier(), event.getProject(), event.getBom());
        try (var ignoredMdcProjectUuid = MDC.putCloseable("projectUuid", ctx.project.getUuid().toString());
             var ignoredMdcProjectName = MDC.putCloseable("projectName", ctx.project.getName());
             var ignoredMdcProjectVersion = MDC.putCloseable("projectVersion", ctx.project.getVersion());
             var ignoredMdcBomUploadToken = MDC.putCloseable("bomUploadToken", ctx.token.toString())) {
            processEvent(ctx, event);
        }
    }

    private void processEvent(final Context ctx, final BomUploadEvent event) {
        final org.cyclonedx.model.Bom cdxBom;
        try {
            final Parser bomParser = BomParserFactory.createParser(event.getBom());
            cdxBom = bomParser.parse(event.getBom());
        } catch (ParseException e) {
            LOGGER.error("Failed to parse BOM", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(NotificationGroup.BOM_PROCESSING_FAILED)
                    .level(NotificationLevel.ERROR)
                    .title(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                    .content("An error occurred while processing a BOM")
                    .subject(new BomProcessingFailed(ctx.project, ctx.bomEncoded, e.getMessage(), ctx.bomFormat, ctx.bomSpecVersion)));
            return;
        }

        ctx.bomSpecVersion = cdxBom.getSpecVersion();
        ctx.bomVersion = cdxBom.getVersion();
        if (cdxBom.getSerialNumber() != null) {
            ctx.bomSerialNumber = cdxBom.getSerialNumber().replaceFirst("^urn:uuid:", "");
        }

        try (var ignoredMdcBomFormat = MDC.putCloseable("bomFormat", ctx.bomFormat.getFormatShortName());
             var ignoredMdcBomSpecVersion = MDC.putCloseable("bomSpecVersion", ctx.bomSpecVersion);
             var ignoredMdcBomSerialNumber = MDC.putCloseable("bomSerialNumber", ctx.bomSerialNumber);
             var ignoredMdcBomVersion = MDC.putCloseable("bomVersion", String.valueOf(ctx.bomVersion))) {
            processBom(ctx, cdxBom);
            eventsToDispatch.forEach(Event::dispatch);
        } catch (RuntimeException e) {
            LOGGER.error("Processing BOM failed", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(NotificationGroup.BOM_PROCESSING_FAILED)
                    .level(NotificationLevel.ERROR)
                    .title(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                    .content("An error occurred while processing a BOM")
                    .subject(new BomProcessingFailed(ctx.project, ctx.bomEncoded, e.getMessage(), ctx.bomFormat, ctx.bomSpecVersion)));
        }
    }

    private void processBom(final Context ctx, final org.cyclonedx.model.Bom cdxBom) {
        LOGGER.info("Consuming uploaded BOM");

        final Project project = convertToProject(cdxBom.getMetadata());
        List<Component> components = new ArrayList<>();
        if (cdxBom.getMetadata() != null && cdxBom.getMetadata().getComponent() != null) {
            components.addAll(convertComponents(cdxBom.getMetadata().getComponent().getComponents()));
        }

        components.addAll(convertComponents(cdxBom.getComponents()));
        components = flatten(components, Component::getChildren, Component::setChildren);
        final int numComponentsTotal = components.size();

        List<ServiceComponent> services = convertServices(cdxBom.getServices());
        services = flatten(services, ServiceComponent::getChildren, ServiceComponent::setChildren);
        final int numServicesTotal = services.size();

        final MultiValuedMap<String, String> dependencyGraph = convertDependencyGraph(cdxBom.getDependencies());

        // Keep track of which BOM ref points to which component identity.
        // During component and service de-duplication, we'll potentially drop
        // some BOM refs, which can break the dependency graph.
        final var identitiesByBomRef = new HashMap<String, ComponentIdentity>();

        // Component identities will change once components are persisted to the database.
        // This means we'll eventually have to update identities in "identitiesByBomRef"
        // for every BOM ref pointing to them.
        // We avoid having to iterate over, and compare, all values of "identitiesByBomRef"
        // by keeping a secondary index on identities to BOM refs.
        // Note: One identity can point to multiple BOM refs, due to component and service de-duplication.
        final var bomRefsByIdentity = new HashSetValuedHashMap<ComponentIdentity, String>();

        components = components.stream().filter(distinctComponentsByIdentity(identitiesByBomRef, bomRefsByIdentity)).toList();
        services = services.stream().filter(distinctServicesByIdentity(identitiesByBomRef, bomRefsByIdentity)).toList();
        LOGGER.info("Consumed %d components (%d before de-duplication) and %d services (%d before de-duplication)"
                .formatted(components.size(), numComponentsTotal, services.size(), numServicesTotal));

        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.BOM_CONSUMED)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.BOM_CONSUMED)
                .content("")
                .subject(new BomConsumedOrProcessed(ctx.project, ctx.bomEncoded, ctx.bomFormat, ctx.bomSpecVersion)));

        final var processedComponents = new ArrayList<Component>();
        try (final var qm = new QueryManager().withL2CacheDisabled()) {
            // Disable reachability checks on commit.
            // See https://www.datanucleus.org/products/accessplatform_4_1/jdo/performance_tuning.html
            //
            // Persistence-by-reachability is an expensive operation that involves traversing the entire
            // object graph, and potentially issuing multiple database operations in doing so.
            //
            // It also enables cascading operations (both for persisting and deleting), but we don't need them here.
            // If this circumstance ever changes, this property may be flicked to "true" again, at the cost of
            // a noticeable performance hit.
            // See:
            //   https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#cascading
            //   https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#_managing_relationships
            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");

            // Save some database round-trips by flushing changes manually.
            // See https://www.datanucleus.org/products/accessplatform_4_1/jdo/performance_tuning.html
            //
            // Note: Queries (SELECT) will always directly hit the database. Using manual flushing means
            // changes made before flush are not visible to queries. If "read-your-writes" is critical,
            // either flush immediately after making changes, or change the FlushMode back to AUTO (the default).
            // AUTO will flush all changes to the database immediately, on every single setter invocation.
            //
            // Another option would be to set FlushMode to QUERY, where flushes will be performed before *any*
            // query. Hibernate has a smart(er) behavior, where it checks if the query "touches" non-flushed
            // data, and only flushes if that's the case. DataNucleus is not as smart, and will always flush.
            // Still, QUERY may be a nice middle-ground between AUTO and MANUAL.
            //
            // BomUploadProcessingTaskTest#informWithBloatedBomTest can be used to profile the impact on large BOMs.
            qm.getPersistenceManager().setProperty(PROPERTY_FLUSH_MODE, FlushMode.MANUAL.name());

            qm.getPersistenceManager().setProperty(PROPERTY_RETAIN_VALUES, "true");

            LOGGER.info("Processing %d components and %s services".formatted(components.size(), services.size()));

            final List<Component> finalComponents = components;
            qm.runInTransaction(() -> {
                final Project persistentProject = processProject(ctx, qm, project);
                final Map<ComponentIdentity, Component> persistentComponentsByIdentity =
                        processComponents(qm, persistentProject, finalComponents, identitiesByBomRef, bomRefsByIdentity);
                processDependencyGraph(qm, persistentProject, dependencyGraph, persistentComponentsByIdentity, identitiesByBomRef);
                recordBomImport(ctx, qm, persistentProject);

                processedComponents.addAll(persistentComponentsByIdentity.values());
            });
        }

        final var vulnAnalysisEvent = new VulnerabilityAnalysisEvent(processedComponents).project(ctx.project);
        vulnAnalysisEvent.setChainIdentifier(ctx.token);
        final List<Component> newComponents = processedComponents.stream()
                .filter(Component::isNew).toList();
        if (!newComponents.isEmpty()) {
            final var newVulnDepAnalysisEvent = new NewVulnerableDependencyAnalysisEvent(newComponents);
            vulnAnalysisEvent.onSuccess(newVulnDepAnalysisEvent);
        }
        vulnAnalysisEvent.onSuccess(new PolicyEvaluationEvent(processedComponents).project(ctx.project));
        eventsToDispatch.add(vulnAnalysisEvent);

        final var rme = new RepositoryMetaEvent(processedComponents);
        rme.onSuccess(new PolicyEvaluationEvent(processedComponents).project(ctx.project));
        eventsToDispatch.add(rme);

        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.BOM_PROCESSED)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.BOM_CONSUMED)
                .content("")
                .subject(new BomConsumedOrProcessed(ctx.project, ctx.bomEncoded, ctx.bomFormat, ctx.bomSpecVersion)));
    }

    private Project processProject(final Context ctx, final QueryManager qm, final Project project) {
        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        query.setFilter("uuid == :uuid");
        query.setParameters(ctx.project.getUuid());
        final Project persistentProject;
        try {
            persistentProject = query.executeUnique();
        } finally {
            query.closeAll();
        }
        if (persistentProject == null) {
            throw new IllegalStateException("Project does not exist");
        }

        if (project != null) {
            boolean hasChanged = false;
            hasChanged |= applyIfChanged(persistentProject, project, Project::getAuthor, persistentProject::setAuthor);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getPublisher, persistentProject::setPublisher);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getManufacturer, persistentProject::setManufacturer);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getSupplier, persistentProject::setSupplier);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getClassifier, persistentProject::setClassifier);
            // TODO: Currently these properties are "decoupled" from the BOM and managed directly by DT users.
            //   Perhaps there could be a flag for BOM uploads saying "use BOM properties" or something?
            // changed |= applyIfChanged(project, metadataComponent, Project::getGroup, project::setGroup);
            // changed |= applyIfChanged(project, metadataComponent, Project::getName, project::setName);
            // changed |= applyIfChanged(project, metadataComponent, Project::getVersion, project::setVersion);
            // changed |= applyIfChanged(project, metadataComponent, Project::getDescription, project::setDescription);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getExternalReferences, persistentProject::setExternalReferences);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getPurl, persistentProject::setPurl);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getSwidTagId, persistentProject::setSwidTagId);

            // BOM ref is transient and thus doesn't count towards the changed status.
            persistentProject.setBomRef(project.getBomRef());

            if (project.getMetadata() != null) {
                final ProjectMetadata projectMetadata = project.getMetadata();
                if (persistentProject.getMetadata() == null) {
                    projectMetadata.setProject(persistentProject);
                    qm.getPersistenceManager().makePersistent(projectMetadata);
                    hasChanged = true;
                } else {
                    hasChanged |= applyIfChanged(persistentProject.getMetadata(), project.getMetadata(), ProjectMetadata::getAuthors, persistentProject.getMetadata()::setAuthors);
                    hasChanged |= applyIfChanged(persistentProject.getMetadata(), project.getMetadata(), ProjectMetadata::getSupplier, persistentProject.getMetadata()::setSupplier);
                }
            }

            if (hasChanged) {
                eventsToDispatch.add(new IndexEvent(IndexEvent.Action.UPDATE, persistentProject));
                qm.getPersistenceManager().flush();
            }
        }

        return persistentProject;
    }

    private Map<ComponentIdentity, Component> processComponents(final QueryManager qm,
                                                                final Project project,
                                                                final List<Component> components,
                                                                final Map<String, ComponentIdentity> identitiesByBomRef,
                                                                final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity) {
        assertPersistent(project, "Project mut be persistent");

        // Fetch IDs of all components that exist in the project already.
        // We'll need them later to determine which components to delete.
        final Set<Long> idsOfComponentsToDelete = getAllComponentIds(qm, project, Component.class);

        // Avoid redundant queries by caching resolved licenses.
        // It is likely that if license IDs were present in a BOM,
        // they appear multiple times for different components.
        final var licenseCache = new HashMap<String, License>();

        // We support resolution of custom licenses by their name.
        // To avoid any conflicts with license IDs, cache those separately.
        final var customLicenseCache = new HashMap<String, License>();

        final var internalComponentIdentifier = new InternalComponentIdentifier();
        final var persistentComponents = new HashMap<ComponentIdentity, Component>();
        for (final Component component : components) {
            component.setInternal(internalComponentIdentifier.isInternal(component));
            resolveAndApplyLicense(qm, component, licenseCache, customLicenseCache);

            final var componentIdentity = new ComponentIdentity(component);
            Component persistentComponent = qm.matchSingleIdentity(project, componentIdentity);
            if (persistentComponent == null) {
                component.setProject(project);
                persistentComponent = qm.getPersistenceManager().makePersistent(component);
                component.setNew(true); // transient
                eventsToDispatch.add(new IndexEvent(IndexEvent.Action.CREATE, persistentComponent));
            } else {
                applyIfChanged(persistentComponent, component, Component::getAuthor, persistentComponent::setAuthor);
                applyIfChanged(persistentComponent, component, Component::getPublisher, persistentComponent::setPublisher);
                applyIfChanged(persistentComponent, component, Component::getSupplier, persistentComponent::setSupplier);
                applyIfChanged(persistentComponent, component, Component::getClassifier, persistentComponent::setClassifier);
                applyIfChanged(persistentComponent, component, Component::getGroup, persistentComponent::setGroup);
                applyIfChanged(persistentComponent, component, Component::getName, persistentComponent::setName);
                applyIfChanged(persistentComponent, component, Component::getVersion, persistentComponent::setVersion);
                applyIfChanged(persistentComponent, component, Component::getDescription, persistentComponent::setDescription);
                applyIfChanged(persistentComponent, component, Component::getCopyright, persistentComponent::setCopyright);
                applyIfChanged(persistentComponent, component, Component::getCpe, persistentComponent::setCpe);
                applyIfChanged(persistentComponent, component, Component::getPurl, persistentComponent::setPurl);
                applyIfChanged(persistentComponent, component, Component::getSwidTagId, persistentComponent::setSwidTagId);
                applyIfChanged(persistentComponent, component, Component::getMd5, persistentComponent::setMd5);
                applyIfChanged(persistentComponent, component, Component::getSha1, persistentComponent::setSha1);
                applyIfChanged(persistentComponent, component, Component::getSha256, persistentComponent::setSha256);
                applyIfChanged(persistentComponent, component, Component::getSha384, persistentComponent::setSha384);
                applyIfChanged(persistentComponent, component, Component::getSha512, persistentComponent::setSha512);
                applyIfChanged(persistentComponent, component, Component::getSha3_256, persistentComponent::setSha3_256);
                applyIfChanged(persistentComponent, component, Component::getSha3_384, persistentComponent::setSha3_384);
                applyIfChanged(persistentComponent, component, Component::getSha3_512, persistentComponent::setSha3_512);
                applyIfChanged(persistentComponent, component, Component::getBlake2b_256, persistentComponent::setBlake2b_256);
                applyIfChanged(persistentComponent, component, Component::getBlake2b_384, persistentComponent::setBlake2b_384);
                applyIfChanged(persistentComponent, component, Component::getBlake2b_512, persistentComponent::setBlake2b_512);
                applyIfChanged(persistentComponent, component, Component::getBlake3, persistentComponent::setBlake3);
                applyIfChanged(persistentComponent, component, Component::getResolvedLicense, persistentComponent::setResolvedLicense);
                applyIfChanged(persistentComponent, component, Component::getLicense, persistentComponent::setLicense);
                applyIfChanged(persistentComponent, component, Component::getLicenseUrl, persistentComponent::setLicenseUrl);
                applyIfChanged(persistentComponent, component, Component::isInternal, persistentComponent::setInternal);
                applyIfChanged(persistentComponent, component, Component::getExternalReferences, persistentComponent::setExternalReferences);
                persistentComponent.setBomRef(component.getBomRef());

                idsOfComponentsToDelete.remove(persistentComponent.getId());
                eventsToDispatch.add(new IndexEvent(IndexEvent.Action.UPDATE, persistentComponent));
            }

            // Update component identities in our Identity->BOMRef map,
            // as after persisting the components, their identities now include UUIDs.
            // Applications like the frontend rely on UUIDs being there.
            final var newIdentity = new ComponentIdentity(persistentComponent);
            final ComponentIdentity oldIdentity = identitiesByBomRef.put(persistentComponent.getBomRef(), newIdentity);
            for (final String bomRef : bomRefsByIdentity.get(oldIdentity)) {
                identitiesByBomRef.put(bomRef, newIdentity);
            }

            persistentComponents.put(newIdentity, persistentComponent);
        }

        qm.getPersistenceManager().flush();

        final long componentsDeleted = deleteComponentsById(qm, idsOfComponentsToDelete);
        if (componentsDeleted > 0) {
            qm.getPersistenceManager().flush();
        }

        return persistentComponents;
    }

    private static Predicate<Component> distinctComponentsByIdentity(final Map<String, ComponentIdentity> identitiesByBomRef,
                                                                     final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity) {
        final var identitiesSeen = new HashSet<ComponentIdentity>();
        return component -> {
            final var componentIdentity = new ComponentIdentity(component);
            identitiesByBomRef.putIfAbsent(component.getBomRef(), componentIdentity);
            bomRefsByIdentity.put(componentIdentity, component.getBomRef());
            return identitiesSeen.add(componentIdentity);
        };
    }

    private static Predicate<ServiceComponent> distinctServicesByIdentity(final Map<String, ComponentIdentity> identitiesByBomRef,
                                                                          final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity) {
        final var identitiesSeen = new HashSet<ComponentIdentity>();
        return service -> {
            final var componentIdentity = new ComponentIdentity(service);
            identitiesByBomRef.putIfAbsent(service.getBomRef(), componentIdentity);
            bomRefsByIdentity.put(componentIdentity, service.getBomRef());
            return identitiesSeen.add(componentIdentity);
        };
    }

    private static <T> Set<Long> getAllComponentIds(final QueryManager qm, final Project project, final Class<T> clazz) {
        final Query<T> query = qm.getPersistenceManager().newQuery(clazz);
        query.setFilter("project == :project");
        query.setParameters(project);
        query.setResult("id");

        try {
            return new HashSet<>(query.executeResultList(Long.class));
        } finally {
            query.closeAll();
        }
    }

    private void recordBomImport(final Context ctx, final QueryManager qm, final Project project) {
        assertPersistent(project, "Project must be persistent");

        final var bomImportDate = new Date();

        final var bom = new Bom();
        bom.setProject(project);
        bom.setBomFormat(ctx.bomFormat);
        bom.setSpecVersion(ctx.bomSpecVersion);
        bom.setSerialNumber(ctx.bomSerialNumber);
        bom.setBomVersion(ctx.bomVersion);
        bom.setImported(bomImportDate);
        qm.getPersistenceManager().makePersistent(bom);

        project.setLastBomImport(bomImportDate);
        project.setLastBomImportFormat("%s %s".formatted(ctx.bomFormat.getFormatShortName(), ctx.bomSpecVersion));
        qm.getPersistenceManager().flush();
    }

    private void processDependencyGraph(final QueryManager qm,
                                        final Project project,
                                        final MultiValuedMap<String, String> dependencyGraph,
                                        final Map<ComponentIdentity, Component> componentsByIdentity,
                                        final Map<String, ComponentIdentity> identitiesByBomRef) {
        assertPersistent(project, "Project must be persistent");

        if (project.getBomRef() != null) {
            final Collection<String> directDependencyBomRefs = dependencyGraph.get(project.getBomRef());
            final String directDependenciesJson = resolveDirectDependenciesJson(project.getBomRef(), directDependencyBomRefs, identitiesByBomRef);
            if (!Objects.equals(directDependenciesJson, project.getDirectDependencies())) {
                project.setDirectDependencies(directDependenciesJson);
                qm.getPersistenceManager().flush();
            }
        } else {
            // Make sure we don't retain stale data from previous BOM uploads.
            if (project.getDirectDependencies() != null) {
                project.setDirectDependencies(null);
                qm.getPersistenceManager().flush();
            }
        }

        for (final Map.Entry<String, ComponentIdentity> entry : identitiesByBomRef.entrySet()) {
            final String componentBomRef = entry.getKey();
            final Collection<String> directDependencyBomRefs = dependencyGraph.get(componentBomRef);
            final String directDependenciesJson = resolveDirectDependenciesJson(componentBomRef, directDependencyBomRefs, identitiesByBomRef);

            final ComponentIdentity dependencyIdentity = identitiesByBomRef.get(entry.getKey());
            final Component component = componentsByIdentity.get(dependencyIdentity);
            // TODO: Check servicesByIdentity when persistentComponent is null
            //   We do not currently store directDependencies for ServiceComponent
            if (component != null) {
                assertPersistent(component, "Component must be persistent");
                if (!Objects.equals(directDependenciesJson, component.getDirectDependencies())) {
                    component.setDirectDependencies(directDependenciesJson);
                }
            } else {
                LOGGER.warn("""
                        Unable to resolve component identity %s to a persistent component; \
                        As a result, the dependency graph will likely be incomplete\
                        """.formatted(dependencyIdentity.toJSON()));
            }
        }

        qm.getPersistenceManager().flush();
    }

    private String resolveDirectDependenciesJson(final String dependencyBomRef,
                                                 final Collection<String> directDependencyBomRefs,
                                                 final Map<String, ComponentIdentity> identitiesByBomRef) {
        if (directDependencyBomRefs == null || directDependencyBomRefs.isEmpty()) {
            return null;
        }

        final var jsonDependencies = new JSONArray();
        for (final String directDependencyBomRef : directDependencyBomRefs) {
            final ComponentIdentity directDependencyIdentity = identitiesByBomRef.get(directDependencyBomRef);
            if (directDependencyIdentity != null) {
                jsonDependencies.put(directDependencyIdentity.toJSON());
            } else {
                LOGGER.warn("""
                        Unable to resolve BOM ref %s to a component identity while processing direct \
                        dependencies of BOM ref %s; As a result, the dependency graph will likely be incomplete\
                        """.formatted(dependencyBomRef, directDependencyBomRef));
            }
        }

        return jsonDependencies.isEmpty() ? null : jsonDependencies.toString();
    }

    private static long deleteComponentsById(final QueryManager qm, final Collection<Long> componentIds) {
        if (componentIds.isEmpty()) {
            return 0;
        }

        final PersistenceManager pm = qm.getPersistenceManager();
        pm.newQuery(AnalysisComment.class, ":ids.contains(analysis.component.id)").deletePersistentAll(componentIds);
        pm.newQuery(Analysis.class, ":ids.contains(component.id)").deletePersistentAll(componentIds);
        pm.newQuery(ViolationAnalysisComment.class, ":ids.contains(violationAnalysis.component.id)").deletePersistentAll(componentIds);
        pm.newQuery(ViolationAnalysis.class, ":ids.contains(component.id)").deletePersistentAll(componentIds);
        pm.newQuery(DependencyMetrics.class, ":ids.contains(component.id)").deletePersistentAll(componentIds);
        pm.newQuery(FindingAttribution.class, ":ids.contains(component.id)").deletePersistentAll(componentIds);
        pm.newQuery(PolicyViolation.class, ":ids.contains(component.id)").deletePersistentAll(componentIds);
        return pm.newQuery(Component.class, ":ids.contains(id)").deletePersistentAll(componentIds);
    }

    private static void resolveAndApplyLicense(final QueryManager qm,
                                               final Component component,
                                               final Map<String, License> licenseCache,
                                               final Map<String, License> customLicenseCache) {
        // CycloneDX components can declare multiple licenses, but we currently
        // only support one. We assume that the licenseCandidates list is ordered
        // by priority, and simply take the first resolvable candidate.
        for (final org.cyclonedx.model.License licenseCandidate : component.getLicenseCandidates()) {
            if (isNotBlank(licenseCandidate.getId())) {
                final License resolvedLicense = licenseCache.computeIfAbsent(licenseCandidate.getId(),
                        licenseId -> resolveLicense(qm, licenseId));
                if (resolvedLicense != null) {
                    component.setResolvedLicense(resolvedLicense);
                    component.setLicenseUrl(trimToNull(licenseCandidate.getUrl()));
                    break;
                }
            }

            if (isNotBlank(licenseCandidate.getName())) {
                final License resolvedCustomLicense = customLicenseCache.computeIfAbsent(licenseCandidate.getName(),
                        licenseName -> resolveCustomLicense(qm, licenseName));
                if (resolvedCustomLicense != null) {
                    component.setResolvedLicense(resolvedCustomLicense);
                    component.setLicenseUrl(trimToNull(licenseCandidate.getUrl()));
                    break;
                }
            }
        }

        // If we were unable to resolve any license by its ID, at least
        // populate the license name. Again assuming order by priority.
        if (component.getResolvedLicense() == null) {
            component.getLicenseCandidates().stream()
                    .filter(license -> isNotBlank(license.getName()))
                    .findFirst()
                    .ifPresent(license -> {
                        component.setLicense(trim(license.getName()));
                        component.setLicenseUrl(trimToNull(license.getUrl()));
                    });
        }
    }

    private static License resolveLicense(final QueryManager qm, final String licenseId) {
        final Query<License> query = qm.getPersistenceManager().newQuery(License.class);
        query.setFilter("licenseId == :licenseId");
        query.setParameters(licenseId);
        try {
            return query.executeUnique();
        } finally {
            query.closeAll();
        }
    }

    private static License resolveCustomLicense(final QueryManager qm, final String licenseName) {
        final Query<License> query = qm.getPersistenceManager().newQuery(License.class);
        query.setFilter("name == :name && customLicense == true");
        query.setParameters(licenseName);
        try {
            return query.executeUnique();
        } finally {
            query.closeAll();
        }
    }

}
