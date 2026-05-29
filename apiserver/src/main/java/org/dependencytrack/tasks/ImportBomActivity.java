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
package org.dependencytrack.tasks;

import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.BomParserFactory;
import org.cyclonedx.parsers.Parser;
import org.datanucleus.flush.FlushMode;
import org.dependencytrack.analysis.AnalyzeProjectWorkflow;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.notification.JdoNotificationEmitter;
import org.dependencytrack.notification.NotificationModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.dependencytrack.pkgmetadata.ResolvePackageMetadataWorkflow;
import org.dependencytrack.proto.internal.workflow.v1.AnalyzeProjectWorkflowArg;
import org.dependencytrack.proto.internal.workflow.v1.ImportBomArg;
import org.dependencytrack.proto.internal.workflow.v1.VulnAnalysisWorkflowContext;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.NoSuchFileException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static javax.jdo.FetchPlan.FETCH_SIZE_GREEDY;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.trim;
import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.apache.commons.lang3.time.DurationFormatUtils.formatDurationHMS;
import static org.datanucleus.PropertyNames.PROPERTY_FLUSH_MODE;
import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.datanucleus.PropertyNames.PROPERTY_RETAIN_VALUES;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_FORMAT;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_SERIAL_NUMBER;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_SPEC_VERSION;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_UPLOAD_TOKEN;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_VERSION;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_BOM_UPLOAD_TOKEN;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;
import static org.dependencytrack.notification.api.NotificationFactory.createBomConsumedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createBomProcessedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createBomProcessingFailedNotification;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertComponents;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertDependencyGraph;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertServices;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertToProject;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertToProjectMetadata;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.flatten;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.createLocalJdbi;
import static org.dependencytrack.proto.internal.workflow.v1.AnalysisTrigger.ANALYSIS_TRIGGER_BOM_UPLOAD;
import static org.dependencytrack.util.PersistenceUtil.applyIfChanged;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

/**
 * @since 5.0.0
 */
@NullMarked
@ActivitySpec(name = "import-bom", defaultTaskQueue = "artifact-imports")
public final class ImportBomActivity implements Activity<ImportBomArg, Void> {

    private static final class ProcessingContext {

        private final UUID token;
        private final Project project;
        private final Bom.Format bomFormat;
        private final long startTimeNs;
        private @Nullable String bomSpecVersion;
        private @Nullable String bomSerialNumber;
        private @Nullable Date bomTimestamp;
        private @Nullable Integer bomVersion;

        private ProcessingContext(UUID token, Project project) {
            this.token = token;
            this.project = project;
            this.bomFormat = Bom.Format.CYCLONEDX;
            this.startTimeNs = System.nanoTime();
        }

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(ImportBomActivity.class);

    private final DexEngine dexEngine;
    private final FileStorage fileStorage;
    private final boolean delayBomProcessedNotification;

    public ImportBomActivity(
            FileStorage fileStorage,
            DexEngine dexEngine,
            boolean delayBomProcessedNotification) {
        this.dexEngine = dexEngine;
        this.fileStorage = fileStorage;
        this.delayBomProcessedNotification = delayBomProcessedNotification;
    }

    @Override
    public @Nullable Void execute(ActivityContext ctx, @Nullable ImportBomArg arg) throws Exception {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        final var token = UUID.fromString(arg.getBomUploadToken());
        final var project = new Project();
        project.setUuid(UUID.fromString(arg.getProjectUuid()));
        project.setName(arg.getProjectName());
        project.setVersion(arg.getProjectVersion().isEmpty() ? null : arg.getProjectVersion());

        final var processCtx = new ProcessingContext(token, project);
        try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, arg.getProjectUuid());
             var _ = MDC.putCloseable(MDC_PROJECT_NAME, arg.getProjectName());
             var _ = MDC.putCloseable(MDC_PROJECT_VERSION, arg.getProjectVersion());
             var _ = MDC.putCloseable(MDC_BOM_UPLOAD_TOKEN, arg.getBomUploadToken())) {
            final byte[] cdxBomBytes;
            try (final InputStream cdxBomStream = fileStorage.get(arg.getBomFileMetadata())) {
                cdxBomBytes = cdxBomStream.readAllBytes();
            } catch (NoSuchFileException e) {
                throw new TerminalApplicationFailureException(e);
            }

            processEvent(processCtx, cdxBomBytes);
        }

        return null;
    }

    private void processEvent(final ProcessingContext ctx, final byte[] cdxBomBytes) {
        final ConsumedBom consumedBom;
        try {
            final Parser parser = BomParserFactory.createParser(cdxBomBytes);
            final var cdxBom = parser.parse(cdxBomBytes);
            ctx.bomSpecVersion = cdxBom.getSpecVersion();
            if (cdxBom.getSerialNumber() != null) {
                ctx.bomSerialNumber = cdxBom.getSerialNumber().replaceFirst("urn:uuid:", "");
            }
            if (cdxBom.getMetadata() != null && cdxBom.getMetadata().getTimestamp() != null) {
                ctx.bomTimestamp = cdxBom.getMetadata().getTimestamp();
            }
            ctx.bomVersion = cdxBom.getVersion();
            consumedBom = consumeBom(cdxBom);
        } catch (ParseException | RuntimeException e) {
            LOGGER.error("Failed to consume BOM", e);
            try (final var qm = new QueryManager()) {
                dispatchBomProcessingFailedNotification(qm, ctx, e);
            }
            throw new TerminalApplicationFailureException("Failed to consume BOM", e);
        }

        dispatchBomConsumedNotification(ctx);

        final ProcessedBom processedBom;
        try (var _ = MDC.putCloseable(MDC_BOM_FORMAT, ctx.bomFormat.getFormatShortName());
             var _ = MDC.putCloseable(MDC_BOM_SPEC_VERSION, ctx.bomSpecVersion);
             var _ = MDC.putCloseable(MDC_BOM_SERIAL_NUMBER, ctx.bomSerialNumber);
             var _ = MDC.putCloseable(MDC_BOM_VERSION, String.valueOf(ctx.bomVersion))) {
            try {
                processedBom = processBom(ctx, consumedBom);
            } catch (Throwable e) {
                LOGGER.error("Failed to process BOM", e);
                try (final var qm = new QueryManager()) {
                    dispatchBomProcessingFailedNotification(qm, ctx, e);
                }
                throw new TerminalApplicationFailureException("Failed to process BOM", e);
            }
        }

        final var processingDurationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - ctx.startTimeNs);
        LOGGER.info("BOM processed successfully in %s".formatted(formatDurationHMS(processingDurationMs)));
        if (!delayBomProcessedNotification) {
            dispatchBomProcessedNotification(ctx);
        }

        final var workflowArgBuilder = AnalyzeProjectWorkflowArg.newBuilder()
                .setProjectUuid(ctx.project.getUuid().toString())
                .setTrigger(ANALYSIS_TRIGGER_BOM_UPLOAD);

        if (!processedBom.components().isEmpty()) {
            final FileMetadata contextFileMetadata = storeVulnAnalysisContext(ctx, processedBom.components());
            if (contextFileMetadata != null) {
                workflowArgBuilder.setContextFileMetadata(contextFileMetadata);
            }
        }

        dexEngine.createRun(
                new CreateWorkflowRunRequest<>(AnalyzeProjectWorkflow.class)
                        .withWorkflowInstanceId("analyze-project:bom-upload:" + ctx.token)
                        .withLabels(Map.ofEntries(
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, ctx.token.toString()),
                                Map.entry(WF_LABEL_PROJECT_UUID, ctx.project.getUuid().toString())))
                        .withConcurrencyKey("analyze-project:" + ctx.project.getUuid())
                        .withPriority(50)
                        .withArgument(workflowArgBuilder.build()));

        if (!processedBom.components().isEmpty()) {
            dexEngine.createRun(
                    new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class)
                            .withWorkflowInstanceId(ResolvePackageMetadataWorkflow.INSTANCE_ID));
        }

    }

    private record ConsumedBom(
            Project project,
            ProjectMetadata projectMetadata,
            List<Component> components,
            List<ServiceComponent> services,
            MultiValuedMap<String, String> dependencyGraph,
            Map<String, ComponentIdentity> identitiesByBomRef,
            MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity
    ) {
    }

    private ConsumedBom consumeBom(final org.cyclonedx.model.Bom cdxBom) {
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

        final ProjectMetadata projectMetadata = convertToProjectMetadata(cdxBom.getMetadata());
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
        final int numDependencyGraphEntries = dependencyGraph.asMap().size();

        components = components.stream().filter(distinctComponentsByIdentity(identitiesByBomRef, bomRefsByIdentity)).toList();
        services = services.stream().filter(distinctServicesByIdentity(identitiesByBomRef, bomRefsByIdentity)).toList();
        LOGGER.info("""
                Consumed %d components (%d before de-duplication), %d services (%d before de-duplication), \
                and %d dependency graph entries""".formatted(components.size(), numComponentsTotal,
                services.size(), numServicesTotal, numDependencyGraphEntries));

        return new ConsumedBom(
                project,
                projectMetadata,
                components,
                services,
                dependencyGraph,
                identitiesByBomRef,
                bomRefsByIdentity
        );
    }

    record ProcessedBom(
            Project project,
            Collection<Component> components,
            Collection<ServiceComponent> services
    ) {
    }

    private ProcessedBom processBom(final ProcessingContext ctx, final ConsumedBom bom) {
        try (final var qm = new QueryManager()) {
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

            // Save some database round-trips by only flushing changes every FLUSH_THRESHOLD write operations.
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
            // ImportBomActivityTest#informWithBloatedBomTest can be used to profile the impact on large BOMs.
            qm.getPersistenceManager().setProperty(PROPERTY_FLUSH_MODE, FlushMode.MANUAL.name());

            // Prevent object fields from being unloaded upon commit.
            //
            // DataNucleus transitions objects into the "hollow" state after the transaction is committed.
            // In hollow state, all fields except the ID are unloaded. Accessing fields afterward triggers
            // one or more database queries to load them again.
            // See https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#lifecycle
            qm.getPersistenceManager().setProperty(PROPERTY_RETAIN_VALUES, "true");

            return qm.callInTransaction(() -> {
                final Project persistentProject = processProject(ctx, qm, bom.project(), bom.projectMetadata());

                LOGGER.info("Processing %d components".formatted(bom.components().size()));
                final Map<ComponentIdentity, Component> persistentComponentsByIdentity =
                        processComponents(qm, persistentProject, bom.components(), bom.identitiesByBomRef(), bom.bomRefsByIdentity());

                LOGGER.info("Processing %d services".formatted(bom.services().size()));
                final Map<ComponentIdentity, ServiceComponent> persistentServicesByIdentity =
                        processServices(qm, persistentProject, bom.services(), bom.identitiesByBomRef(), bom.bomRefsByIdentity());

                LOGGER.info("Processing %d dependency graph entries".formatted(bom.dependencyGraph().asMap().size()));
                processDependencyGraph(qm, persistentProject, bom.dependencyGraph(), persistentComponentsByIdentity,
                        bom.identitiesByBomRef(), bom.bomRefsByIdentity());

                recordBomImport(ctx, qm, persistentProject);

                return new ProcessedBom(
                        persistentProject,
                        persistentComponentsByIdentity.values(),
                        persistentServicesByIdentity.values()
                );
            });
        }
    }

    private static Project processProject(
            final ProcessingContext ctx,
            final QueryManager qm,
            final Project project,
            final ProjectMetadata projectMetadata
    ) {
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

        boolean hasChanged = false;
        if (project != null) {
            persistentProject.setBomRef(project.getBomRef()); // Transient
            hasChanged |= applyIfChanged(persistentProject, project, Project::getAuthors, persistentProject::setAuthors);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getPublisher, persistentProject::setPublisher);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getClassifier, persistentProject::setClassifier);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getSupplier, persistentProject::setSupplier);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getManufacturer, persistentProject::setManufacturer);
            // TODO: Currently these properties are "decoupled" from the BOM and managed directly by DT users.
            //   Perhaps there could be a flag for BOM uploads saying "use BOM properties" or something?
            // hasChanged |= applyIfChanged(persistentProject, project, Project::getGroup, persistentProject::setGroup);
            // hasChanged |= applyIfChanged(persistentProject, project, Project::getName, persistentProject::setName);
            // hasChanged |= applyIfChanged(persistentProject, project, Project::getVersion, persistentProject::setVersion);
            // hasChanged |= applyIfChanged(persistentProject, project, Project::getDescription, persistentProject::setDescription);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getExternalReferences, persistentProject::setExternalReferences);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getCpe, persistentProject::setCpe);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getPurl, persistentProject::setPurl);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getSwidTagId, persistentProject::setSwidTagId);
        }

        if (projectMetadata != null) {
            if (persistentProject.getMetadata() == null) {
                projectMetadata.setProject(persistentProject);
                qm.getPersistenceManager().makePersistent(projectMetadata);
                hasChanged = true;
            } else {
                hasChanged |= applyIfChanged(persistentProject.getMetadata(), projectMetadata, ProjectMetadata::getAuthors,
                        authors -> persistentProject.getMetadata().setAuthors(authors != null ? new ArrayList<>(authors) : null));
                hasChanged |= applyIfChanged(persistentProject.getMetadata(), projectMetadata, ProjectMetadata::getSupplier, persistentProject.getMetadata()::setSupplier);
                hasChanged |= applyIfChanged(persistentProject.getMetadata(), projectMetadata, ProjectMetadata::getTools, persistentProject.getMetadata()::setTools);
            }
        }

        if (hasChanged) {
            qm.getPersistenceManager().flush();
        }

        return persistentProject;
    }

    private static Map<ComponentIdentity, Component> processComponents(
            final QueryManager qm,
            final Project project,
            final List<Component> components,
            final Map<String, ComponentIdentity> identitiesByBomRef,
            final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity
    ) {
        assertPersistent(project, "Project must be persistent");

        // Avoid redundant queries by caching resolved licenses.
        // It is likely that if license IDs were present in a BOM,
        // they appear multiple times for different components.
        final var licenseCache = new HashMap<String, License>();

        // We support resolution of custom licenses by their name.
        // To avoid any conflicts with license IDs, cache those separately.
        final var customLicenseCache = new HashMap<String, License>();

        final var internalComponentIdentifier = new InternalComponentIdentifier();

        final List<Component> persistentComponents = getAllComponents(qm, project);

        // Group existing components by their identity for easier lookup.
        // Note that we exclude the UUID from the identity here,
        // since incoming non-persistent components won't have one yet.
        final Map<ComponentIdentity, Component> persistentComponentByIdentity = persistentComponents.stream()
                .collect(Collectors.toMap(
                        component -> new ComponentIdentity(component, /* excludeUuid */ true),
                        Function.identity(),
                        (previous, duplicate) -> {
                            LOGGER.warn("""
                                    More than one existing component matches the identity %s; \
                                    Proceeding with first match, others will be deleted\
                                    """.formatted(new ComponentIdentity(previous, /* excludeUuid */ true)));
                            return previous;
                        }));

        final Set<Long> idsOfComponentsToDelete = persistentComponents.stream()
                .map(Component::getId)
                .collect(Collectors.toSet());

        for (final Component component : components) {
            component.setInternal(internalComponentIdentifier.isInternal(component));
            resolveAndApplyLicense(qm, component, licenseCache, customLicenseCache);

            final var componentIdentity = new ComponentIdentity(component);
            Component persistentComponent = persistentComponentByIdentity.get(componentIdentity);
            if (persistentComponent == null) {
                component.setProject(project);
                persistentComponent = qm.getPersistenceManager().makePersistent(component);
                persistentComponent.setNew(true); // Transient
            } else {
                persistentComponent.setBomRef(component.getBomRef()); // Transient
                applyIfChanged(persistentComponent, component, Component::getAuthors, persistentComponent::setAuthors);
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
                applyIfChanged(persistentComponent, component, Component::getLicenseExpression, persistentComponent::setLicenseExpression);
                applyIfChanged(persistentComponent, component, Component::isInternal, persistentComponent::setInternal);
                applyIfChanged(persistentComponent, component, Component::getExternalReferences, persistentComponent::setExternalReferences);
                applyIfChanged(persistentComponent, component, Component::getScope, persistentComponent::setScope);

                qm.synchronizeComponentOccurrences(persistentComponent, component.getOccurrences());
                qm.synchronizeComponentProperties(persistentComponent, component.getProperties());
                idsOfComponentsToDelete.remove(persistentComponent.getId());
            }

            // Update component identities in our Identity->BOMRef map,
            // as after persisting the components, their identities now include UUIDs.
            final var newIdentity = new ComponentIdentity(persistentComponent);
            final ComponentIdentity oldIdentity = identitiesByBomRef.put(persistentComponent.getBomRef(), newIdentity);
            for (final String bomRef : bomRefsByIdentity.get(oldIdentity)) {
                identitiesByBomRef.put(bomRef, newIdentity);
            }

            persistentComponentByIdentity.put(newIdentity, persistentComponent);
        }

        persistentComponentByIdentity.entrySet().removeIf(entry -> {
            // Remove entries for identities without UUID, those were only needed for matching.
            final ComponentIdentity identity = entry.getKey();
            if (identity.getUuid() == null) {
                return true;
            }

            // Remove entries for components marked for deletion.
            final Component component = entry.getValue();
            return idsOfComponentsToDelete.contains(component.getId());
        });

        qm.getPersistenceManager().flush();

        final long componentsDeleted = deleteComponentsById(qm, idsOfComponentsToDelete);
        if (componentsDeleted > 0) {
            qm.getPersistenceManager().flush();
        }

        return persistentComponentByIdentity;
    }

    private static Map<ComponentIdentity, ServiceComponent> processServices(
            final QueryManager qm,
            final Project project,
            final List<ServiceComponent> services,
            final Map<String, ComponentIdentity> identitiesByBomRef,
            final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity
    ) {
        assertPersistent(project, "Project must be persistent");

        final List<ServiceComponent> persistentServices = getAllServices(qm, project);

        // Group existing services by their identity for easier lookup.
        // Note that we exclude the UUID from the identity here,
        // since incoming non-persistent services won't have one yet.
        final Map<ComponentIdentity, ServiceComponent> persistentServiceByIdentity = persistentServices.stream()
                .collect(Collectors.toMap(
                        service -> new ComponentIdentity(service, /* excludeUuid */ true),
                        Function.identity(),
                        (previous, duplicate) -> {
                            LOGGER.warn("""
                                    More than one existing service matches the identity %s; \
                                    Proceeding with first match, others will be deleted\
                                    """.formatted(new ComponentIdentity(previous, /* excludeUuid */ true)));
                            return previous;
                        }));

        final Set<Long> idsOfServicesToDelete = persistentServices.stream()
                .map(ServiceComponent::getId)
                .collect(Collectors.toSet());

        for (final ServiceComponent service : services) {
            final var componentIdentity = new ComponentIdentity(service);
            ServiceComponent persistentService = persistentServiceByIdentity.get(componentIdentity);
            if (persistentService == null) {
                service.setProject(project);
                persistentService = qm.getPersistenceManager().makePersistent(service);
            } else {
                persistentService.setBomRef(service.getBomRef()); // Transient
                applyIfChanged(persistentService, service, ServiceComponent::getGroup, persistentService::setGroup);
                applyIfChanged(persistentService, service, ServiceComponent::getName, persistentService::setName);
                applyIfChanged(persistentService, service, ServiceComponent::getVersion, persistentService::setVersion);
                applyIfChanged(persistentService, service, ServiceComponent::getDescription, persistentService::setDescription);
                applyIfChanged(persistentService, service, ServiceComponent::getAuthenticated, persistentService::setAuthenticated);
                applyIfChanged(persistentService, service, ServiceComponent::getCrossesTrustBoundary, persistentService::setCrossesTrustBoundary);
                applyIfChanged(persistentService, service, ServiceComponent::getExternalReferences, persistentService::setExternalReferences);
                applyIfChanged(persistentService, service, ServiceComponent::getProvider, persistentService::setProvider);
                applyIfChanged(persistentService, service, ServiceComponent::getData, persistentService::setData);
                applyIfChanged(persistentService, service, ServiceComponent::getEndpoints, persistentService::setEndpoints);
                idsOfServicesToDelete.remove(persistentService.getId());
            }

            // Update component identities in our Identity->BOMRef map,
            // as after persisting the services, their identities now include UUIDs.
            final var newIdentity = new ComponentIdentity(persistentService);
            final ComponentIdentity oldIdentity = identitiesByBomRef.put(service.getBomRef(), newIdentity);
            for (final String bomRef : bomRefsByIdentity.get(oldIdentity)) {
                identitiesByBomRef.put(bomRef, newIdentity);
            }

            persistentServiceByIdentity.put(newIdentity, persistentService);
        }

        persistentServiceByIdentity.entrySet().removeIf(entry -> {
            // Remove entries for identities without UUID, those were only needed for matching.
            final ComponentIdentity identity = entry.getKey();
            if (identity.getUuid() == null) {
                return true;
            }

            // Remove entries for services marked for deletion.
            final ServiceComponent service = entry.getValue();
            return idsOfServicesToDelete.contains(service.getId());
        });

        qm.getPersistenceManager().flush();

        final long servicesDeleted = deleteServicesById(qm, idsOfServicesToDelete);
        if (servicesDeleted > 0) {
            qm.getPersistenceManager().flush();
        }

        return persistentServiceByIdentity;
    }

    private void processDependencyGraph(
            final QueryManager qm,
            final Project project,
            final MultiValuedMap<String, String> dependencyGraph,
            final Map<ComponentIdentity, Component> componentsByIdentity,
            final Map<String, ComponentIdentity> identitiesByBomRef,
            final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity
    ) {
        assertPersistent(project, "Project must be persistent");

        if (project.getBomRef() != null) {
            final Collection<String> directDependencyBomRefs = dependencyGraph.get(project.getBomRef());
            if (directDependencyBomRefs == null || directDependencyBomRefs.isEmpty()) {
                LOGGER.warn("""
                        The dependency graph has %d entries, but the project (metadata.component node of the BOM) \
                        is not one of them; Graph will be incomplete because it is not possible to determine its root\
                        """.formatted(dependencyGraph.size()));
            }
            final String directDependenciesJson = resolveDependenciesJson(
                    List.of(project.getBomRef()),
                    sourceBomRef -> sourceBomRef.equals(project.getBomRef()) ? directDependencyBomRefs : null,
                    identitiesByBomRef);
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

        for (final Component component : componentsByIdentity.values()) {
            assertPersistent(component, "Component must be persistent");
            final String mergedDirectDependenciesJson = resolveMergedDirectDependenciesJson(
                    component, dependencyGraph, identitiesByBomRef, bomRefsByIdentity);
            if (!Objects.equals(mergedDirectDependenciesJson, component.getDirectDependencies())) {
                component.setDirectDependencies(mergedDirectDependenciesJson);
            }
        }

        qm.getPersistenceManager().flush();

        try (final Handle jdbiHandle = createLocalJdbi(qm).open()) {
            jdbiHandle.attach(ComponentDao.class).setDirect(project.getId());
        }
    }

    private static void recordBomImport(final ProcessingContext ctx, final QueryManager qm, final Project project) {
        assertPersistent(project, "Project must be persistent");

        final var bomImportDate = new Date();

        final var bom = new Bom();
        bom.setProject(project);
        bom.setBomFormat(ctx.bomFormat);
        bom.setSpecVersion(ctx.bomSpecVersion);
        bom.setSerialNumber(ctx.bomSerialNumber);
        bom.setBomVersion(ctx.bomVersion);
        bom.setImported(bomImportDate);
        bom.setGenerated(ctx.bomTimestamp);
        qm.getPersistenceManager().makePersistent(bom);

        project.setLastBomImport(bomImportDate);
        project.setLastBomImportFormat("%s %s".formatted(ctx.bomFormat.getFormatShortName(), ctx.bomSpecVersion));
    }

    /**
     * Builds {@code directDependencies} JSON for one component by merging direct dependency edges from every BOM ref
     * that maps to the same deduplicated identity.
     * <p>
     * {@link #distinctComponentsByIdentity} records those refs under {@code bomRefsByIdentity} using identities from
     * consumption (UUID usually unset). After persist, {@link ComponentIdentity#equals(Object)} includes UUID, so we
     * look up with {@code new ComponentIdentity(component, true)} — same structural key as at consumption, same pattern
     * as matching existing rows in {@link #processComponents}.
     */
    private @Nullable String resolveMergedDirectDependenciesJson(
            final Component component,
            final MultiValuedMap<String, String> dependencyGraph,
            final Map<String, ComponentIdentity> identitiesByBomRef,
            final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity
    ) {
        final Collection<String> sourceBomRefs = bomRefsByIdentity.get(
                new ComponentIdentity(component, /* excludeUuid */ true));
        if (sourceBomRefs == null || sourceBomRefs.isEmpty()) {
            return null;
        }

        return resolveDependenciesJson(sourceBomRefs, dependencyGraph::get, identitiesByBomRef);
    }

    private @Nullable String resolveDependenciesJson(
            final Collection<String> sourceBomRefs,
            final Function<String, Collection<String>> directDependencyBomRefsProvider,
            final Map<String, ComponentIdentity> identitiesByBomRef
    ) {
        if (sourceBomRefs == null || sourceBomRefs.isEmpty()) {
            return null;
        }

        final var jsonDependencies = Mappers.jsonMapper().createArrayNode();
        final var directDependencyIdentitiesSeen = new HashSet<ComponentIdentity>();

        for (final String sourceBomRef : sourceBomRefs) {
            final Collection<String> directDependencyBomRefs = directDependencyBomRefsProvider.apply(sourceBomRef);
            if (directDependencyBomRefs == null || directDependencyBomRefs.isEmpty()) {
                continue;
            }

            for (final String directDependencyBomRef : directDependencyBomRefs) {
                final ComponentIdentity directDependencyIdentity = identitiesByBomRef.get(directDependencyBomRef);
                if (directDependencyIdentity != null) {
                    if (!directDependencyIdentitiesSeen.add(directDependencyIdentity)) {
                        LOGGER.debug("Omitting duplicate direct dependency %s for BOM ref %s"
                                .formatted(directDependencyBomRef, sourceBomRef));
                        continue;
                    }
                    jsonDependencies.add(directDependencyIdentity.toJSON());
                } else {
                    LOGGER.warn("""
                            Unable to resolve BOM ref %s to a component identity while processing direct \
                            dependencies of BOM ref %s; As a result, the dependency graph will likely be incomplete\
                            """.formatted(sourceBomRef, directDependencyBomRef));
                }
            }
        }

        return jsonDependencies.isEmpty() ? null : jsonDependencies.toString();
    }

    private static long deleteComponentsById(final QueryManager qm, final Collection<Long> componentIds) {
        if (componentIds.isEmpty()) {
            return 0;
        }

        final PersistenceManager pm = qm.getPersistenceManager();
        LOGGER.info("Deleting %d component(s) that are no longer part of the project".formatted(componentIds.size()));
        return pm.newQuery(Component.class, ":ids.contains(id)").deletePersistentAll(componentIds);
    }

    private static long deleteServicesById(final QueryManager qm, final Collection<Long> serviceIds) {
        if (serviceIds.isEmpty()) {
            return 0;
        }

        final PersistenceManager pm = qm.getPersistenceManager();
        LOGGER.info("Deleting %d service(s) that are no longer part of the project".formatted(serviceIds.size()));
        return pm.newQuery(ServiceComponent.class, ":ids.contains(id)").deletePersistentAll(serviceIds);
    }

    private static void resolveAndApplyLicense(
            final QueryManager qm,
            final Component component,
            final Map<String, License> licenseCache,
            final Map<String, License> customLicenseCache
    ) {
        // CycloneDX components can declare multiple licenses, but we currently
        // only support one. We assume that the licenseCandidates list is ordered
        // by priority, and simply take the first resolvable candidate.
        for (final org.cyclonedx.model.License licenseCandidate : component.getLicenseCandidates()) {
            if (isNotBlank(licenseCandidate.getId())) {
                final License resolvedLicense = licenseCache.computeIfAbsent(licenseCandidate.getId(), qm::getLicenseByIdOrName);
                if (resolvedLicense != License.UNRESOLVED) {
                    component.setResolvedLicense(resolvedLicense);
                    component.setLicenseUrl(trimToNull(licenseCandidate.getUrl()));
                    break;
                }
            }

            if (isNotBlank(licenseCandidate.getName())) {
                final License resolvedLicense = licenseCache.computeIfAbsent(licenseCandidate.getName(), qm::getLicenseByIdOrName);
                if (resolvedLicense != License.UNRESOLVED) {
                    component.setResolvedLicense(resolvedLicense);
                    component.setLicenseUrl(trimToNull(licenseCandidate.getUrl()));
                    break;
                }

                final License resolvedCustomLicense = customLicenseCache.computeIfAbsent(
                        licenseCandidate.getName(), qm::getCustomLicenseByName);
                if (resolvedCustomLicense != License.UNRESOLVED) {
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

    private static List<Component> getAllComponents(final QueryManager qm, final Project project) {
        final Query<Component> query = qm.getPersistenceManager().newQuery(Component.class);
        query.getFetchPlan().addGroup(Component.FetchGroup.BOM_UPLOAD_PROCESSING.name());
        query.getFetchPlan().setFetchSize(FETCH_SIZE_GREEDY);
        query.setFilter("project.id == :projectId");
        query.setParameters(project.getId());

        try {
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

    private static List<ServiceComponent> getAllServices(final QueryManager qm, final Project project) {
        final Query<ServiceComponent> query = qm.getPersistenceManager().newQuery(ServiceComponent.class);
        query.getFetchPlan().setFetchSize(FETCH_SIZE_GREEDY);
        query.setFilter("project.id == :projectId");
        query.setParameters(project.getId());

        try {
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

    private static Predicate<Component> distinctComponentsByIdentity(
            final Map<String, ComponentIdentity> identitiesByBomRef,
            final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity
    ) {
        final var identitiesSeen = new HashSet<ComponentIdentity>();
        return component -> {
            final var componentIdentity = new ComponentIdentity(component);

            final boolean isBomRefUnique = identitiesByBomRef.putIfAbsent(component.getBomRef(), componentIdentity) == null;
            if (!isBomRefUnique) {
                LOGGER.warn("""
                        BOM ref %s is associated with multiple components in the BOM; \
                        BOM refs are required to be unique; Please report this to the vendor \
                        of the tool that generated the BOM""".formatted(component.getBomRef()));
            }

            bomRefsByIdentity.put(componentIdentity, component.getBomRef());

            final boolean isSeenBefore = !identitiesSeen.add(componentIdentity);
            if (LOGGER.isDebugEnabled() && isSeenBefore) {
                LOGGER.debug("Filtering component with BOM ref %s and identity %s due to duplicate identity"
                        .formatted(component.getBomRef(), componentIdentity.toJSON()));
            }

            return !isSeenBefore;
        };
    }

    private static Predicate<ServiceComponent> distinctServicesByIdentity(
            final Map<String, ComponentIdentity> identitiesByBomRef,
            final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity
    ) {
        final var identitiesSeen = new HashSet<ComponentIdentity>();
        return service -> {
            final var componentIdentity = new ComponentIdentity(service);
            identitiesByBomRef.putIfAbsent(service.getBomRef(), componentIdentity);
            bomRefsByIdentity.put(componentIdentity, service.getBomRef());
            final boolean isSeenBefore = !identitiesSeen.add(componentIdentity);
            if (LOGGER.isDebugEnabled() && isSeenBefore) {
                LOGGER.debug("Filtering service with BOM ref %s and identity %s due to duplicate identity"
                        .formatted(service.getBomRef(), componentIdentity.toJSON()));
            }

            return !isSeenBefore;
        };
    }

    private void dispatchBomConsumedNotification(final ProcessingContext ctx) {
        try (final var qm = new QueryManager()) {
            new JdoNotificationEmitter(qm).emit(
                    createBomConsumedNotification(
                            NotificationModelConverter.convert(ctx.project),
                            ctx.bomFormat.getFormatShortName(),
                            ctx.bomSpecVersion,
                            ctx.token.toString()));
        }
    }

    private void dispatchBomProcessedNotification(final ProcessingContext ctx) {
        try (final var qm = new QueryManager()) {
            new JdoNotificationEmitter(qm).emit(
                    createBomProcessedNotification(
                            NotificationModelConverter.convert(ctx.project),
                            ctx.bomFormat.getFormatShortName(),
                            ctx.bomSpecVersion,
                            ctx.token.toString()));
        }
    }

    private void dispatchBomProcessingFailedNotification(
            final QueryManager qm, final ProcessingContext ctx, final Throwable throwable) {
        new JdoNotificationEmitter(qm).emit(
                createBomProcessingFailedNotification(
                        NotificationModelConverter.convert(ctx.project),
                        ctx.bomFormat.getFormatShortName(),
                        ctx.bomSpecVersion,
                        ctx.token.toString(),
                        throwable.getMessage()));
    }

    private @Nullable FileMetadata storeVulnAnalysisContext(ProcessingContext ctx, Collection<Component> components) {
        final List<Long> newComponentIds = components.stream()
                .filter(Component::isNew)
                .map(Component::getId)
                .toList();
        if (newComponentIds.isEmpty()) {
            return null;
        }

        final var context = VulnAnalysisWorkflowContext.newBuilder()
                .addAllNewComponentIds(newComponentIds)
                .build();

        try {
            return fileStorage.store(
                    "vuln-analysis/context/%s.proto".formatted(ctx.token),
                    "application/protobuf",
                    new ByteArrayInputStream(context.toByteArray()));
        } catch (Exception e) {
            LOGGER.warn("""
                    Failed to store vuln analysis context; \
                    NEW_VULNERABLE_DEPENDENCY notifications will not be emitted""", e);
            return null;
        }
    }

}
