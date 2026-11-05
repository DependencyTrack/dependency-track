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

import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.BomParserFactory;
import org.cyclonedx.parsers.Parser;
import org.dependencytrack.analysis.AnalyzeProjectWorkflow;
import org.dependencytrack.analysis.ProjectLastAnalysisDao;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.notification.JdoNotificationEmitter;
import org.dependencytrack.notification.NotificationModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.ComponentLicenseDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.pkgmetadata.PackageMetadataResolutionDao;
import org.dependencytrack.pkgmetadata.ResolvePackageMetadataWorkflow;
import org.dependencytrack.proto.internal.workflow.v1.AnalyzeProjectWorkflowArg;
import org.dependencytrack.proto.internal.workflow.v1.ImportBomArg;
import org.dependencytrack.proto.internal.workflow.v1.VulnAnalysisWorkflowContext;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.NoSuchFileException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNullElse;
import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.apache.commons.lang3.time.DurationFormatUtils.formatDurationHMS;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_FORMAT;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_SERIAL_NUMBER;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_SPEC_VERSION;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_UPLOAD_TOKEN;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_VERSION;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_ANALYSIS_TRIGGER;
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
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.proto.internal.workflow.v1.AnalysisTrigger.ANALYSIS_TRIGGER_BOM_UPLOAD;

/**
 * @since 5.0.0
 */
@NullMarked
@ActivitySpec(name = "import-bom", defaultTaskQueue = "artifact-imports")
public final class ImportBomActivity implements Activity<ImportBomArg, Void> {

    private static final class ProcessingContext {

        private final UUID token;
        private final Project project;
        private final long startTimeNs;
        private @Nullable String bomSpecVersion;
        private @Nullable String bomSerialNumber;
        private @Nullable Date bomTimestamp;
        private @Nullable Integer bomVersion;

        private ProcessingContext(UUID token, Project project) {
            this.token = token;
            this.project = project;
            this.startTimeNs = System.nanoTime();
        }
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(ImportBomActivity.class);
    private static final String BOM_FORMAT = "CycloneDX";

    private final DexEngine dexEngine;
    private final FileStorage fileStorage;
    private final boolean delayBomProcessedNotification;

    public ImportBomActivity(FileStorage fileStorage, DexEngine dexEngine, boolean delayBomProcessedNotification) {
        this.dexEngine = dexEngine;
        this.fileStorage = fileStorage;
        this.delayBomProcessedNotification = delayBomProcessedNotification;
    }

    @Override
    public @Nullable Void execute(ActivityContext ctx, @Nullable ImportBomArg arg)
            throws IOException, InterruptedException {
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

    private void processEvent(final ProcessingContext ctx, final byte[] cdxBomBytes) throws InterruptedException {
        final ConsumedBom consumedBom;
        try {
            final Parser parser = BomParserFactory.createParser(cdxBomBytes);
            final Bom cdxBom = parser.parse(cdxBomBytes);
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

        if (Thread.interrupted()) {
            throw new InterruptedException("Interrupted before the BOM could be processed");
        }

        dispatchBomConsumedNotification(ctx);

        try (var _ = MDC.putCloseable(MDC_BOM_FORMAT, BOM_FORMAT);
                var _ = MDC.putCloseable(MDC_BOM_SPEC_VERSION, ctx.bomSpecVersion);
                var _ = MDC.putCloseable(MDC_BOM_SERIAL_NUMBER, ctx.bomSerialNumber);
                var _ = MDC.putCloseable(MDC_BOM_VERSION, String.valueOf(ctx.bomVersion))) {
            try {
                processBom(ctx, consumedBom);
            } catch (InterruptedException e) {
                throw e;
            } catch (Throwable e) {
                LOGGER.error("Failed to process BOM", e);
                try (final var qm = new QueryManager()) {
                    dispatchBomProcessingFailedNotification(qm, ctx, e);
                }
                throw new TerminalApplicationFailureException("Failed to process BOM", e);
            }
        }

        final var processingDurationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - ctx.startTimeNs);
        LOGGER.info("BOM processed successfully in {}", formatDurationHMS(processingDurationMs));
        if (!delayBomProcessedNotification) {
            dispatchBomProcessedNotification(ctx);
        }

        final var workflowArgBuilder = AnalyzeProjectWorkflowArg.newBuilder()
                .setProjectUuid(ctx.project.getUuid().toString())
                .setTrigger(ANALYSIS_TRIGGER_BOM_UPLOAD);

        if (!consumedBom.components().isEmpty()) {
            final FileMetadata contextFileMetadata = storeVulnAnalysisContext(ctx, consumedBom.components());
            if (contextFileMetadata != null) {
                workflowArgBuilder.setContextFileMetadata(contextFileMetadata);
            }
        }

        final UUID analysisRunId = dexEngine.createRun(new CreateWorkflowRunRequest<>(AnalyzeProjectWorkflow.class)
                .withWorkflowInstanceId(AnalyzeProjectWorkflow.instanceIdForBomUpload(ctx.token))
                .withLabels(Map.ofEntries(
                        Map.entry(
                                WF_LABEL_ANALYSIS_TRIGGER,
                                AnalyzeProjectWorkflow.triggerLabelValue(ANALYSIS_TRIGGER_BOM_UPLOAD)),
                        Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, ctx.token.toString()),
                        Map.entry(WF_LABEL_PROJECT_UUID, ctx.project.getUuid().toString())))
                .withConcurrencyKey(AnalyzeProjectWorkflow.concurrencyKeyForProject(ctx.project.getUuid()))
                .withPriority(50)
                .withArgument(workflowArgBuilder.build()));
        if (analysisRunId != null) {
            useJdbiTransaction(handle ->
                    handle.attach(ProjectLastAnalysisDao.class).recordAttempt(ctx.project.getUuid(), Instant.now()));
        }

        if (!consumedBom.components().isEmpty()) {
            dexEngine.createRun(new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class)
                    .withWorkflowInstanceId(ResolvePackageMetadataWorkflow.INSTANCE_ID));
        }
    }

    private record ConsumedBom(
            @Nullable Project project,
            @Nullable ProjectMetadata projectMetadata,
            List<Component> components,
            List<ServiceComponent> services,
            Map<String, Set<String>> dependencyGraph,
            Map<String, ComponentIdentity> identitiesByBomRef,
            Map<ComponentIdentity, Set<String>> bomRefsByIdentity) {}

    private ConsumedBom consumeBom(final Bom cdxBom) {
        // Keep track of which BOM ref points to which component identity.
        // During component and service de-duplication, we'll potentially drop
        // some BOM refs, which can break the dependency graph.
        final var identitiesByBomRef = new HashMap<String, ComponentIdentity>();

        // Component identities will change once components are assigned their UUIDs.
        // This means we'll eventually have to update identities in "identitiesByBomRef"
        // for every BOM ref pointing to them.
        // We avoid having to iterate over, and compare, all values of "identitiesByBomRef"
        // by keeping a secondary index on identities to BOM refs.
        // Note: One identity can point to multiple BOM refs, due to component and service de-duplication.
        final var bomRefsByIdentity = new HashMap<ComponentIdentity, Set<String>>();

        final ProjectMetadata projectMetadata = convertToProjectMetadata(cdxBom.getMetadata());
        final Project project = convertToProject(cdxBom.getMetadata());
        List<Component> components = new ArrayList<>();
        if (cdxBom.getMetadata() != null && cdxBom.getMetadata().getComponent() != null) {
            components.addAll(
                    convertComponents(cdxBom.getMetadata().getComponent().getComponents()));
        }

        components.addAll(convertComponents(cdxBom.getComponents()));
        components = flatten(components, Component::getChildren, Component::setChildren);
        final int numComponentsTotal = components.size();

        List<ServiceComponent> services = convertServices(cdxBom.getServices());
        services = flatten(services, ServiceComponent::getChildren, ServiceComponent::setChildren);
        final int numServicesTotal = services.size();

        final Map<String, Set<String>> dependencyGraph = convertDependencyGraph(cdxBom.getDependencies());
        final int numDependencyGraphEntries = dependencyGraph.size();

        components = components.stream()
                .filter(distinctComponentsByIdentity(identitiesByBomRef, bomRefsByIdentity))
                .toList();
        services = services.stream()
                .filter(distinctServicesByIdentity(identitiesByBomRef, bomRefsByIdentity))
                .toList();
        LOGGER.info(
                """
                Consumed {} components ({} before de-duplication), {} services ({} before de-duplication), \
                and {} dependency graph entries\
                """,
                components.size(),
                numComponentsTotal,
                services.size(),
                numServicesTotal,
                numDependencyGraphEntries);

        return new ConsumedBom(
                project, projectMetadata, components, services, dependencyGraph, identitiesByBomRef, bomRefsByIdentity);
    }

    private static void processBom(ProcessingContext ctx, ConsumedBom bom) throws InterruptedException {
        useJdbiTransaction(handle -> {
            final var dao = new BomImportDao(handle);

            final Long projectId = handle.attach(ProjectDao.class).getProjectId(ctx.project.getUuid());
            if (projectId == null) {
                throw new IllegalStateException("Project does not exist");
            }

            if (bom.project() != null) {
                dao.updateProject(projectId, bom.project());
            }
            if (bom.projectMetadata() != null) {
                dao.upsertProjectMetadata(projectId, bom.projectMetadata());
            }

            final Map<String, Long> licenseIds = dao.getLicenseIdsByIdOrName(bom.components().stream()
                    .flatMap(component -> component.getLicenseCandidates().stream())
                    .flatMap(license -> Stream.of(license.getId(), license.getName()))
                    .filter(StringUtils::isNotBlank)
                    .collect(Collectors.toSet()));

            LOGGER.info("Processing {} components", bom.components().size());
            reconcileComponents(dao, projectId, bom, licenseIds);

            LOGGER.info("Processing {} services", bom.services().size());
            reconcileServices(dao, projectId, bom);

            LOGGER.info(
                    "Processing {} dependency graph entries",
                    bom.dependencyGraph().size());
            final String projectDirectDependencies = processDependencyGraph(bom);

            dao.createComponents(
                    projectId,
                    bom.components().stream().filter(Component::isNew).toList());
            dao.updateComponents(bom.components().stream()
                    .filter(component -> !component.isNew())
                    .toList());

            dao.createServices(
                    projectId,
                    bom.services().stream()
                            .filter(service -> service.getId() == 0)
                            .toList());
            dao.updateServices(bom.services().stream()
                    .filter(service -> service.getId() != 0)
                    .toList());

            synchronizeComponentProperties(dao, projectId, bom.components());
            synchronizeComponentOccurrences(dao, projectId, bom.components());
            synchronizeComponentLicenses(dao, projectId, bom.components(), licenseIds);

            dao.recordBomImport(
                    projectId,
                    projectDirectDependencies,
                    BOM_FORMAT,
                    ctx.bomSpecVersion,
                    ctx.bomSerialNumber,
                    ctx.bomVersion,
                    ctx.bomTimestamp);
            new PackageMetadataResolutionDao(handle).seedPending(projectId);
        });
    }

    private static void reconcileComponents(
            BomImportDao dao, long projectId, ConsumedBom bom, Map<String, Long> licenseIds)
            throws InterruptedException {
        final List<Component> components = bom.components();

        final var internalComponentIdentifier = new InternalComponentIdentifier();

        final List<BomImportDao.ExistingComponentRow> existingComponents = dao.getExistingComponents(projectId);

        final Map<ComponentIdentity, BomImportDao.ExistingComponentRow> existingComponentByIdentity =
                existingComponents.stream()
                        .collect(Collectors.toMap(
                                BomImportDao.ExistingComponentRow::identity, Function.identity(), (previous, _) -> {
                                    LOGGER.warn("""
                                        More than one existing component matches the identity {}; \
                                        Proceeding with first match, others will be deleted\
                                        """, previous.identity().toJSON());
                                    return previous;
                                }));

        final Set<Long> idsOfComponentsToDelete = existingComponents.stream()
                .map(BomImportDao.ExistingComponentRow::id)
                .collect(Collectors.toSet());

        for (final Component component : components) {
            component.setInternal(internalComponentIdentifier.isInternal(component));
            applyPrimaryLicense(component, licenseIds);

            final BomImportDao.ExistingComponentRow existingComponent =
                    existingComponentByIdentity.get(new ComponentIdentity(component));
            if (existingComponent == null) {
                // Direct dependencies reference UUIDs, so UUIDs must be known before anything is inserted.
                component.setUuid(UUID.randomUUID());
                component.setNew(true);
            } else {
                component.setId(existingComponent.id());
                component.setUuid(existingComponent.uuid());
                idsOfComponentsToDelete.remove(existingComponent.id());
            }

            final var oldIdentity = new ComponentIdentity(component, /* excludeUuid */ true);
            final var newIdentity = new ComponentIdentity(component);
            for (final String bomRef : bom.bomRefsByIdentity().getOrDefault(oldIdentity, Set.of())) {
                bom.identitiesByBomRef().put(bomRef, newIdentity);
            }
        }

        if (!idsOfComponentsToDelete.isEmpty()) {
            LOGGER.info(
                    "Deleting {} component(s) that are no longer part of the project", idsOfComponentsToDelete.size());
            dao.deleteComponents(idsOfComponentsToDelete);
        }
    }

    private static void reconcileServices(BomImportDao dao, long projectId, ConsumedBom bom)
            throws InterruptedException {
        final List<BomImportDao.ExistingServiceRow> existingServices = dao.getExistingServices(projectId);

        final Map<ComponentIdentity, BomImportDao.ExistingServiceRow> existingServiceByIdentity =
                existingServices.stream()
                        .collect(Collectors.toMap(
                                BomImportDao.ExistingServiceRow::identity, Function.identity(), (previous, _) -> {
                                    LOGGER.warn("""
                                        More than one existing service matches the identity {}; \
                                        Proceeding with first match, others will be deleted\
                                        """, previous.identity().toJSON());
                                    return previous;
                                }));

        final Set<Long> idsOfServicesToDelete = existingServices.stream()
                .map(BomImportDao.ExistingServiceRow::id)
                .collect(Collectors.toSet());

        for (final ServiceComponent service : bom.services()) {
            final BomImportDao.ExistingServiceRow existingService =
                    existingServiceByIdentity.get(new ComponentIdentity(service));
            if (existingService == null) {
                service.setUuid(UUID.randomUUID());
            } else {
                service.setId(existingService.id());
                service.setUuid(existingService.uuid());
                idsOfServicesToDelete.remove(existingService.id());
            }

            final var oldIdentity = new ComponentIdentity(service, /* excludeUuid */ true);
            final var newIdentity = new ComponentIdentity(service);
            for (final String bomRef : bom.bomRefsByIdentity().getOrDefault(oldIdentity, Set.of())) {
                bom.identitiesByBomRef().put(bomRef, newIdentity);
            }
        }

        if (!idsOfServicesToDelete.isEmpty()) {
            LOGGER.info("Deleting {} service(s) that are no longer part of the project", idsOfServicesToDelete.size());
            dao.deleteServices(idsOfServicesToDelete);
        }
    }

    private static @Nullable String processDependencyGraph(ConsumedBom bom) {
        for (final Component component : bom.components()) {
            // Merges the edges of every BOM ref that was de-duplicated into this component.
            final Set<String> sourceBomRefs = bom.bomRefsByIdentity()
                    .getOrDefault(new ComponentIdentity(component, /* excludeUuid */ true), Set.of());
            component.setDirectDependencies(
                    resolveDependencies(sourceBomRefs, bom.dependencyGraph(), bom.identitiesByBomRef()));
        }

        if (bom.project() == null) {
            return null;
        }

        final String projectBomRef = bom.project().getBomRef();
        final Collection<String> directDependencyBomRefs = bom.dependencyGraph().get(projectBomRef);
        if (directDependencyBomRefs == null || directDependencyBomRefs.isEmpty()) {
            LOGGER.warn("""
                The dependency graph has {} entries, but the project (metadata.component node of the BOM) \
                is not one of them; Graph will be incomplete because it is not possible to determine its root\
                """, bom.dependencyGraph().size());
        }
        return resolveDependencies(List.of(projectBomRef), bom.dependencyGraph(), bom.identitiesByBomRef());
    }

    private static void synchronizeComponentProperties(BomImportDao dao, long projectId, List<Component> components)
            throws InterruptedException {
        final var propertiesToCreate = new ArrayList<ComponentProperty>();
        final var idsOfPropertiesToDelete = new ArrayList<Long>();
        synchronizeComponentOwnedRows(
                components,
                dao.getComponentProperties(projectId),
                Component::getProperties,
                ComponentProperty.Identity::new,
                (component, property) -> {
                    property.setComponent(component);
                    propertiesToCreate.add(property);
                },
                idsOfPropertiesToDelete::add);
        dao.deleteComponentProperties(idsOfPropertiesToDelete);
        dao.createComponentProperties(propertiesToCreate);
    }

    private static void synchronizeComponentOccurrences(BomImportDao dao, long projectId, List<Component> components)
            throws InterruptedException {
        final var occurrencesToCreate = new ArrayList<ComponentOccurrence>();
        final var idsOfOccurrencesToDelete = new ArrayList<UUID>();
        synchronizeComponentOwnedRows(
                components,
                dao.getComponentOccurrences(projectId),
                Component::getOccurrences,
                ComponentOccurrence.Identity::of,
                (component, occurrence) -> {
                    occurrence.setComponent(component);
                    occurrencesToCreate.add(occurrence);
                },
                idsOfOccurrencesToDelete::add);
        dao.deleteComponentOccurrences(idsOfOccurrencesToDelete);
        dao.createComponentOccurrences(occurrencesToCreate);
    }

    private static void synchronizeComponentLicenses(
            BomImportDao dao, long projectId, List<Component> components, Map<String, Long> licenseIds)
            throws InterruptedException {
        final var rowsToCreate = new ArrayList<ComponentLicenseDao.ComponentLicenseRow>();
        final var idsOfRowsToDelete = new ArrayList<Long>();
        synchronizeComponentOwnedRows(
                components,
                dao.getComponentLicenses(projectId),
                component -> buildComponentLicenseRows(component, licenseIds),
                Function.identity(),
                (_, row) -> rowsToCreate.add(row),
                idsOfRowsToDelete::add);
        dao.deleteComponentLicenses(idsOfRowsToDelete);
        dao.createComponentLicenses(rowsToCreate);
    }

    private static List<ComponentLicenseDao.ComponentLicenseRow> buildComponentLicenseRows(
            Component component, Map<String, Long> licenseIds) {
        // Keyed by license to satisfy the COMPONENTLICENSES_ID_IDX unique index.
        final var rowsByKey = new LinkedHashMap<String, ComponentLicenseDao.ComponentLicenseRow>();
        final String expression = trimToNull(component.getLicenseExpression());
        // Only one row may hold the expression, per the COMPONENTLICENSES_EXP_IDX unique index.
        boolean expressionAssigned = false;

        for (final org.cyclonedx.model.License candidate : component.getLicenseCandidates()) {
            Long licenseId = candidate.getId() != null ? licenseIds.get(candidate.getId()) : null;
            if (licenseId == null && candidate.getName() != null) {
                licenseId = licenseIds.get(candidate.getName());
            }

            final String name =
                    StringUtils.firstNonBlank(trimToNull(candidate.getName()), trimToNull(candidate.getId()));
            if (licenseId == null && name == null) {
                continue;
            }

            final String key = licenseId != null ? "resolved:" + licenseId : "unresolved:" + name;
            if (rowsByKey.containsKey(key)) {
                continue;
            }

            final boolean isExpression = !expressionAssigned
                    && expression != null
                    && (expression.equals(candidate.getId()) || expression.equals(candidate.getName()));
            expressionAssigned |= isExpression;
            rowsByKey.put(
                    key,
                    new ComponentLicenseDao.ComponentLicenseRow(
                            component.getId(),
                            licenseId,
                            licenseId == null ? name : null,
                            isExpression ? expression : null,
                            trimToNull(candidate.getUrl()),
                            rowsByKey.size() + 1,
                            "DECLARED"));
        }

        // Expressions are a valid substitute for license objects, so they need a row of their own.
        if (expression != null && !expressionAssigned) {
            rowsByKey.put(
                    "expression",
                    new ComponentLicenseDao.ComponentLicenseRow(
                            component.getId(), null, null, expression, null, rowsByKey.size() + 1, "DECLARED"));
        }

        return List.copyOf(rowsByKey.values());
    }

    private static <T, R extends BomImportDao.ComponentOwnedRow<I, K>, I, K> void synchronizeComponentOwnedRows(
            List<Component> components,
            List<R> existingRows,
            Function<Component, @Nullable Collection<T>> incomingGetter,
            Function<T, K> identityOf,
            BiConsumer<Component, T> onCreate,
            Consumer<I> onDelete) {
        final Map<Long, List<R>> existingRowsByComponentId =
                existingRows.stream().collect(Collectors.groupingBy(BomImportDao.ComponentOwnedRow::componentId));

        for (final Component component : components) {
            final var incomingByIdentity = new LinkedHashMap<K, T>();
            final Collection<T> incoming = incomingGetter.apply(component);
            if (incoming != null) {
                for (final T item : incoming) {
                    incomingByIdentity.putIfAbsent(identityOf.apply(item), item);
                }
            }

            final var identitiesSeen = new HashSet<K>();
            for (final R existingRow : existingRowsByComponentId.getOrDefault(component.getId(), List.of())) {
                // Older versions could store duplicate rows.
                final boolean isDuplicate = !identitiesSeen.add(existingRow.identity());
                if (isDuplicate || !incomingByIdentity.containsKey(existingRow.identity())) {
                    onDelete.accept(existingRow.id());
                }
            }

            incomingByIdentity.forEach((identity, item) -> {
                if (!identitiesSeen.contains(identity)) {
                    onCreate.accept(component, item);
                }
            });
        }
    }

    private static @Nullable String resolveDependencies(
            Collection<String> sourceBomRefs,
            Map<String, Set<String>> dependencyGraph,
            Map<String, ComponentIdentity> identitiesByBomRef) {
        final var jsonDependencies = Mappers.jsonMapper().createArrayNode();
        final var directDependencyIdentitiesSeen = new HashSet<ComponentIdentity>();

        // Iterate in a stable order to ensure that the generated JSON array
        // is identical across BOM uploads with unchanged data, and doesn't cause
        // unnecessary DB updates.
        final List<String> sortedSourceBomRefs = sourceBomRefs.stream().sorted().toList();

        for (final String sourceBomRef : sortedSourceBomRefs) {
            final Collection<String> directDependencyBomRefs = dependencyGraph.get(sourceBomRef);
            if (directDependencyBomRefs == null || directDependencyBomRefs.isEmpty()) {
                continue;
            }

            final List<String> sortedDirectDependencyBomRefs =
                    directDependencyBomRefs.stream().sorted().toList();

            for (final String directDependencyBomRef : sortedDirectDependencyBomRefs) {
                final ComponentIdentity directDependencyIdentity = identitiesByBomRef.get(directDependencyBomRef);
                if (directDependencyIdentity != null) {
                    if (!directDependencyIdentitiesSeen.add(directDependencyIdentity)) {
                        LOGGER.debug(
                                "Omitting duplicate direct dependency {} for BOM ref {}",
                                directDependencyBomRef,
                                sourceBomRef);
                        continue;
                    }
                    jsonDependencies.add(directDependencyIdentity.toJSON());
                } else {
                    LOGGER.warn("""
                        Unable to resolve BOM ref {} to a component identity while processing direct \
                        dependencies of BOM ref {}; As a result, the dependency graph will likely be incomplete\
                        """, directDependencyBomRef, sourceBomRef);
                }
            }
        }

        return jsonDependencies.isEmpty() ? null : jsonDependencies.toString();
    }

    private static void applyPrimaryLicense(Component component, Map<String, Long> licenseIds) {
        // The component's own columns hold one license: the first resolved row, else the first named one.
        final List<ComponentLicenseDao.ComponentLicenseRow> rows = buildComponentLicenseRows(component, licenseIds);
        rows.stream()
                .filter(row -> row.licenseId() != null)
                .findFirst()
                .or(() -> rows.stream().filter(row -> row.license() != null).findFirst())
                .ifPresent(row -> {
                    if (row.licenseId() != null) {
                        final var license = new License();
                        license.setId(row.licenseId());
                        component.setResolvedLicense(license);
                    } else {
                        component.setLicense(row.license());
                    }
                    component.setLicenseUrl(row.licenseUrl());
                });
    }

    private static Predicate<Component> distinctComponentsByIdentity(
            final Map<String, ComponentIdentity> identitiesByBomRef,
            final Map<ComponentIdentity, Set<String>> bomRefsByIdentity) {
        final var identitiesSeen = new HashSet<ComponentIdentity>();
        return component -> {
            final var componentIdentity = new ComponentIdentity(component);

            final boolean isBomRefUnique =
                    identitiesByBomRef.putIfAbsent(component.getBomRef(), componentIdentity) == null;
            if (!isBomRefUnique) {
                LOGGER.warn("""
                    BOM ref {} is associated with multiple components in the BOM; \
                    BOM refs are required to be unique; Please report this to the vendor \
                    of the tool that generated the BOM\
                    """, component.getBomRef());
            }

            bomRefsByIdentity
                    .computeIfAbsent(componentIdentity, _ -> new HashSet<>())
                    .add(component.getBomRef());

            final boolean isSeenBefore = !identitiesSeen.add(componentIdentity);
            if (LOGGER.isDebugEnabled() && isSeenBefore) {
                LOGGER.debug(
                        "Filtering component with BOM ref {} and identity {} due to duplicate identity",
                        component.getBomRef(),
                        componentIdentity.toJSON());
            }

            return !isSeenBefore;
        };
    }

    private static Predicate<ServiceComponent> distinctServicesByIdentity(
            final Map<String, ComponentIdentity> identitiesByBomRef,
            final Map<ComponentIdentity, Set<String>> bomRefsByIdentity) {
        final var identitiesSeen = new HashSet<ComponentIdentity>();
        return service -> {
            final var componentIdentity = new ComponentIdentity(service);
            identitiesByBomRef.putIfAbsent(service.getBomRef(), componentIdentity);
            bomRefsByIdentity
                    .computeIfAbsent(componentIdentity, _ -> new HashSet<>())
                    .add(service.getBomRef());
            final boolean isSeenBefore = !identitiesSeen.add(componentIdentity);
            if (LOGGER.isDebugEnabled() && isSeenBefore) {
                LOGGER.debug(
                        "Filtering service with BOM ref {} and identity {} due to duplicate identity",
                        service.getBomRef(),
                        componentIdentity.toJSON());
            }

            return !isSeenBefore;
        };
    }

    private void dispatchBomConsumedNotification(final ProcessingContext ctx) {
        try (final var qm = new QueryManager()) {
            new JdoNotificationEmitter(qm)
                    .emit(createBomConsumedNotification(
                            NotificationModelConverter.convert(ctx.project),
                            BOM_FORMAT,
                            ctx.bomSpecVersion,
                            ctx.token.toString()));
        }
    }

    private void dispatchBomProcessedNotification(final ProcessingContext ctx) {
        try (final var qm = new QueryManager()) {
            new JdoNotificationEmitter(qm)
                    .emit(createBomProcessedNotification(
                            NotificationModelConverter.convert(ctx.project),
                            BOM_FORMAT,
                            ctx.bomSpecVersion,
                            ctx.token.toString()));
        }
    }

    private void dispatchBomProcessingFailedNotification(
            final QueryManager qm, final ProcessingContext ctx, final Throwable throwable) {
        new JdoNotificationEmitter(qm)
                .emit(createBomProcessingFailedNotification(
                        NotificationModelConverter.convert(ctx.project),
                        BOM_FORMAT,
                        ctx.bomSpecVersion,
                        ctx.token.toString(),
                        requireNonNullElse(
                                throwable.getMessage(), throwable.getClass().getName())));
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
                NEW_VULNERABLE_DEPENDENCY notifications will not be emitted\
                """, e);
            return null;
        }
    }
}
