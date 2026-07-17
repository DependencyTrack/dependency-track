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
package org.dependencytrack.vulnanalysis;

import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.cyclonedx.proto.v1_7.VulnerabilityReference;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.FindingAttributionKey;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
import org.dependencytrack.persistence.jdbi.AnalysisDao;
import org.dependencytrack.persistence.jdbi.AnalysisDao.Analysis;
import org.dependencytrack.persistence.jdbi.AnalysisDao.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.NotificationSubjectDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityAliasDao;
import org.dependencytrack.persistence.jdbi.query.GetProjectAuditChangeNotificationSubjectQuery;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.policy.PolicyEvaluationDeadline;
import org.dependencytrack.policy.PolicyEvaluationTimedOutException;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyEvaluator;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyOperation;
import org.dependencytrack.proto.internal.workflow.v1.AnalysisTrigger;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileVulnAnalysisResultsArg;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileVulnAnalysisResultsArg.AnalyzerResult;
import org.dependencytrack.proto.internal.workflow.v1.VulnAnalysisWorkflowContext;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.InputStream;
import java.nio.file.NoSuchFileException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Gatherers;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;
import static java.util.Objects.requireNonNullElse;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_ANALYZER_NAME;
import static org.dependencytrack.notification.api.NotificationFactory.createAnalyzerErrorNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createNewVulnerabilityNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createNewVulnerableDependencyNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createVulnerabilityAnalysisDecisionChangeNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createVulnerabilityRetractedNotification;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.0.0
 */
@ActivitySpec(name = "reconcile-vuln-analysis-results", defaultTaskQueue = "vuln-analysis-reconciliations")
public final class ReconcileVulnAnalysisResultsActivity implements Activity<ReconcileVulnAnalysisResultsArg, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ReconcileVulnAnalysisResultsActivity.class);

    private static final String INTERNAL_VULN_ID_PROPERTY = "dependencytrack:internal:vulnerability-id";
    private static final String REFERENCE_URL_PROPERTY = "dependency-track:vuln:reference-url";
    private static final int SYNC_BATCH_SIZE = 100;

    private final FileStorage fileStorage;
    private final PluginManager pluginManager;
    private final VulnerabilityPolicyEvaluator vulnPolicyEvaluator;
    private final Duration maxEvaluationDuration;

    public ReconcileVulnAnalysisResultsActivity(
            FileStorage fileStorage,
            PluginManager pluginManager,
            VulnerabilityPolicyEvaluator vulnPolicyEvaluator,
            Duration maxEvaluationDuration) {
        this.fileStorage = fileStorage;
        this.pluginManager = pluginManager;
        this.vulnPolicyEvaluator = vulnPolicyEvaluator;
        this.maxEvaluationDuration = requireNonNull(maxEvaluationDuration, "maxEvaluationDuration must not be null");
        if (!maxEvaluationDuration.isPositive()) {
            throw new IllegalArgumentException("maxEvaluationDuration must be positive");
        }
    }

    @Override
    public @Nullable Void execute(
            ActivityContext ctx,
            @Nullable ReconcileVulnAnalysisResultsArg arg) throws Exception {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        final var projectUuid = UUID.fromString(arg.getProjectUuid());

        try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, projectUuid.toString())) {
            LOGGER.debug(
                    "Reconciling results from {} vulnerability analyzers",
                    arg.getAnalyzerResultsCount());

            final var failedAnalyzers = new HashSet<String>();
            final var reportedFindings = new ArrayList<ReportedFinding>();
            final var vulnDetailsByKey = new HashMap<VulnerabilityKey, ReportedVulnerability>();
            final var vulnAliasAssertionsByAnalyzer = new HashMap<String, Map<VulnerabilityKey, Set<VulnerabilityKey>>>();

            // Sort analyzer results by name for deterministic merge order.
            // When multiple analyzers report the same vulnerability,
            // we'll only use the data of the first one.
            final var sortedResults = new ArrayList<>(arg.getAnalyzerResultsList());
            sortedResults.sort(Comparator.comparing(AnalyzerResult::getAnalyzerName));

            for (final AnalyzerResult result : sortedResults) {
                if (Thread.interrupted()) {
                    throw new InterruptedException("Interrupted before processing analyzer result");
                }

                final String analyzerName = result.getAnalyzerName();
                try (var _ = MDC.putCloseable(MDC_VULN_ANALYZER_NAME, analyzerName)) {
                    LOGGER.debug("Processing analyzer results");

                    if (!result.getSuccessful()) {
                        LOGGER.debug("Analyzer failed");
                        failedAnalyzers.add(analyzerName);
                        continue;
                    }

                    if (!result.hasVdrFileMetadata()) {
                        LOGGER.debug("Analyzer did not produce any results");
                        continue;
                    }

                    final Bom vdr;
                    try (final InputStream vdrInputStream = fileStorage.get(result.getVdrFileMetadata())) {
                        vdr = Bom.parseFrom(vdrInputStream);
                    } catch (NoSuchFileException e) {
                        LOGGER.warn("Could not find VDR file from analyzer; Considering it to have failed", e);
                        failedAnalyzers.add(analyzerName);
                        continue;
                    }

                    collectFindingsFromVdr(analyzerName, vdr, reportedFindings, vulnDetailsByKey, vulnAliasAssertionsByAnalyzer);
                }
            }

            if (arg.getAnalyzerResultsCount() == failedAnalyzers.size()) {
                LOGGER.warn("No successful analyzers; skipping reconciliation");
                return null;
            }

            LOGGER.debug(
                    "Collected {} findings and {} unique vulnerabilities from VDRs",
                    reportedFindings.size(),
                    vulnDetailsByKey.size());

            final List<Vulnerability> convertedVulns = convertVulns(vulnDetailsByKey);
            LOGGER.debug("Converted {} vulnerabilities", convertedVulns.size());

            final var vulnUpdatePolicy = new VulnerabilityUpdatePolicy(pluginManager);

            final Map<VulnerabilityKey, Long> vulnDbIdByVulnKey =
                    syncVulns(convertedVulns, vulnUpdatePolicy::isUpdatableByAnalyzer);
            LOGGER.debug("Synchronized {} vulnerabilities", vulnDbIdByVulnKey.size());

            syncVulnAliasAssertions(vulnAliasAssertionsByAnalyzer);

            reconcileFindings(
                    arg,
                    projectUuid,
                    reportedFindings,
                    vulnDbIdByVulnKey,
                    failedAnalyzers,
                    ctx);
        }

        return null;
    }

    private record ReportedVulnerability(
            org.cyclonedx.proto.v1_7.Vulnerability vdrVuln,
            @Nullable Long internalVulnId) {
    }

    private record ReportedFinding(
            long componentId,
            VulnerabilityKey vulnKey,
            String analyzerName,
            @Nullable String referenceUrl) {
    }

    private static void collectFindingsFromVdr(
            String analyzerName,
            Bom vdr,
            List<ReportedFinding> findings,
            Map<VulnerabilityKey, ReportedVulnerability> reportedVulnByVulnKey,
            Map<String, Map<VulnerabilityKey, Set<VulnerabilityKey>>> aliasAssertionsByAnalyzer) {
        for (final org.cyclonedx.proto.v1_7.Vulnerability vdrVuln : vdr.getVulnerabilitiesList()) {
            var source = Vulnerability.Source.ofName(vdrVuln.getSource().getName());
            if (source == null) {
                source = requireNonNullElse(
                        Vulnerability.Source.ofVulnId(vdrVuln.getId()),
                        Vulnerability.Source.UNKNOWN);
            }
            final var vulnKey = new VulnerabilityKey(vdrVuln.getId(), source);

            final Long internalVulnId = extractInternalVulnId(vdrVuln);
            final String referenceUrl = extractReferenceUrl(vdrVuln);

            if (internalVulnId == null && source != Vulnerability.Source.UNKNOWN) {
                // Ensure that each vulnerability reported by an analyzer has alias assertions,
                // even if the assertions set is empty. This is the only way we can detect whether
                // a previously reported alias has been removed.
                //
                // Note that this does not apply to the internal analyzer, since it can't report
                // aliases we don't already have in the database.
                final Map<VulnerabilityKey, Set<VulnerabilityKey>> analyzerAssertions =
                        aliasAssertionsByAnalyzer.computeIfAbsent(analyzerName, _ -> new HashMap<>());
                analyzerAssertions.computeIfAbsent(vulnKey, _ -> new HashSet<>());

                for (final VulnerabilityReference vdrVulnRef : vdrVuln.getReferencesList()) {
                    var refSource = Vulnerability.Source.ofName(vdrVulnRef.getSource().getName());
                    if (refSource == null) {
                        refSource = Vulnerability.Source.ofVulnId(vdrVulnRef.getId());
                    }
                    if (refSource == null || refSource == Vulnerability.Source.UNKNOWN) {
                        LOGGER.debug("Skipping alias reference with unknown source for vulnerability '{}'", vulnKey);
                        continue;
                    }

                    final var aliasKey = new VulnerabilityKey(vdrVulnRef.getId(), refSource);
                    if (!aliasKey.equals(vulnKey)) {
                        analyzerAssertions.get(vulnKey).add(aliasKey);
                    }
                }
            }

            reportedVulnByVulnKey.merge(
                    vulnKey,
                    new ReportedVulnerability(vdrVuln, internalVulnId),
                    (existing, incoming) -> {
                        if (existing.internalVulnId() != null) {
                            return existing;
                        }
                        if (incoming.internalVulnId() != null) {
                            return incoming;
                        }

                        return existing;
                    });

            for (final VulnerabilityAffects affects : vdrVuln.getAffectsList()) {
                try {
                    final long componentId = Long.parseLong(affects.getRef());
                    findings.add(new ReportedFinding(componentId, vulnKey, analyzerName, referenceUrl));
                } catch (NumberFormatException e) {
                    LOGGER.warn(
                            "Encountered invalid BOM ref '{}' for vulnerability '{}'",
                            affects.getRef(),
                            vulnKey,
                            e);
                }
            }
        }
    }

    private static @Nullable Long extractInternalVulnId(org.cyclonedx.proto.v1_7.Vulnerability vuln) {
        for (final Property prop : vuln.getPropertiesList()) {
            if (INTERNAL_VULN_ID_PROPERTY.equals(prop.getName())) {
                try {
                    return Long.parseLong(prop.getValue());
                } catch (NumberFormatException e) {
                    LOGGER.warn("Invalid internal vulnerability ID: {}", prop.getValue());
                }
            }
        }

        return null;
    }

    private static @Nullable String extractReferenceUrl(org.cyclonedx.proto.v1_7.Vulnerability vuln) {
        for (final Property prop : vuln.getPropertiesList()) {
            if (REFERENCE_URL_PROPERTY.equals(prop.getName())
                    && (prop.getValue().startsWith("http://") || prop.getValue().startsWith("https://"))) {
                return prop.getValue();
            }
        }

        return null;
    }

    private List<Vulnerability> convertVulns(
            Map<VulnerabilityKey, ReportedVulnerability> reportedVulnByVulnKey) {
        if (reportedVulnByVulnKey.isEmpty()) {
            return List.of();
        }

        final var converted = new ArrayList<Vulnerability>(reportedVulnByVulnKey.size());

        for (final var entry : reportedVulnByVulnKey.entrySet()) {
            final VulnerabilityKey vulnKey = entry.getKey();
            final ReportedVulnerability reportedVuln = entry.getValue();

            if (reportedVuln.internalVulnId() != null) {
                final var vuln = new Vulnerability();
                vuln.setId(reportedVuln.internalVulnId());
                vuln.setVulnId(vulnKey.vulnId());
                vuln.setSource(vulnKey.source());
                converted.add(vuln);
                continue;
            }

            try {
                final Vulnerability vuln = BovModelConverter.convert(
                        Bom.newBuilder()
                                .addVulnerabilities(reportedVuln.vdrVuln())
                                .build(),
                        reportedVuln.vdrVuln(),
                        false);
                converted.add(vuln);
            } catch (RuntimeException e) {
                LOGGER.warn("Failed to convert vulnerability {}: {}", vulnKey, e.getMessage());
            }
        }

        return converted;
    }

    private Map<VulnerabilityKey, Long> syncVulns(
            List<Vulnerability> vulns,
            Predicate<String> canUpdatePredicate) throws InterruptedException {
        final var syncedVulns = new HashMap<VulnerabilityKey, Long>(vulns.size());

        for (final var batch : (Iterable<List<Vulnerability>>) () -> vulns.stream()
                .gather(Gatherers.windowFixed(SYNC_BATCH_SIZE))
                .iterator()) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before synchronizing vulnerability batch");
            }

            syncedVulns.putAll(syncVulnsBatch(batch, canUpdatePredicate));
        }

        return syncedVulns;
    }

    private Map<VulnerabilityKey, Long> syncVulnsBatch(
            Collection<Vulnerability> vulns,
            Predicate<String> canUpdatePredicate) {
        if (vulns.isEmpty()) {
            return Map.of();
        }

        LOGGER.debug("Synchronizing batch of {} vulnerabilities", vulns.size());

        return inJdbiTransaction(handle -> new VulnerabilityDao(handle).syncAll(vulns, canUpdatePredicate));
    }

    private void syncVulnAliasAssertions(Map<String, Map<VulnerabilityKey, Set<VulnerabilityKey>>> aliasAssertionsByAnalyzer) throws InterruptedException {
        for (final var entry : aliasAssertionsByAnalyzer.entrySet()) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before synchronizing alias assertions");
            }

            final String analyzerName = entry.getKey();
            final Map<VulnerabilityKey, Set<VulnerabilityKey>> aliasAssertions = entry.getValue();

            LOGGER.debug("Synchronizing {} alias assertions for analyzer '{}'", aliasAssertions.size(), analyzerName);
            useJdbiTransaction(handle -> new VulnerabilityAliasDao(handle)
                    .syncAssertions("vuln-analyzer:" + analyzerName, aliasAssertions));
        }
    }

    private void reconcileFindings(
            ReconcileVulnAnalysisResultsArg arg,
            UUID projectUuid,
            List<ReportedFinding> reportedFindings,
            Map<VulnerabilityKey, Long> vulnDbIdByVulnKey,
            Set<String> failedAnalyzers,
            ActivityContext activityContext) throws InterruptedException {
        final Long projectId = withJdbiHandle(
                handle -> handle.attach(ProjectDao.class).getProjectId(projectUuid));
        if (projectId == null) {
            throw new TerminalApplicationFailureException("Project does not exist");
        }

        // Fetch all existing finding attributions for the project.
        // This excludes attributions that have previously been soft-deleted.
        // Group them by finding key for easier access during reconciliation.
        final List<FindingDao.FindingAttribution> existingAttributions =
                withJdbiHandle(handle -> new FindingDao(handle).getExistingAttributions(projectId));
        final Map<FindingKey, List<FindingDao.FindingAttribution>> existingAttributionsByFindingKey =
                existingAttributions.stream()
                        .collect(Collectors.groupingBy(
                                attribution -> new FindingKey(attribution.componentId(), attribution.vulnDbId())));

        LOGGER.debug(
                "Found {} existing finding attribution(s) and {} unique finding(s)",
                existingAttributions.size(),
                existingAttributionsByFindingKey.size());

        final var findingsToCreate = new HashSet<FindingKey>();
        final var createAttributionCommands = new HashSet<FindingDao.CreateAttributionCommand>();
        final var reportedAttributionKeys = new HashSet<FindingAttributionKey>();

        for (final ReportedFinding reportedFinding : reportedFindings) {
            final Long vulnDbId = vulnDbIdByVulnKey.get(reportedFinding.vulnKey());
            if (vulnDbId == null) {
                LOGGER.warn(
                        "Vulnerability {} not found in database; Skipping",
                        reportedFinding.vulnKey());
                continue;
            }

            reportedAttributionKeys.add(
                    new FindingAttributionKey(
                            new FindingKey(reportedFinding.componentId(), vulnDbId),
                            reportedFinding.analyzerName()));

            final var findingKey = new FindingKey(reportedFinding.componentId(), vulnDbId);
            final List<FindingDao.FindingAttribution> existingFindingAttributionsForKey =
                    existingAttributionsByFindingKey.get(findingKey);

            final boolean findingExists =
                    existingFindingAttributionsForKey != null
                            && !existingFindingAttributionsForKey.isEmpty();
            if (!findingExists) {
                findingsToCreate.add(findingKey);
            }

            final boolean hasAttribution =
                    existingFindingAttributionsForKey != null
                            && existingFindingAttributionsForKey.stream()
                            .anyMatch(ef -> ef.analyzerName().equals(reportedFinding.analyzerName()));
            if (!hasAttribution) {
                createAttributionCommands.add(
                        new FindingDao.CreateAttributionCommand(
                                vulnDbId,
                                reportedFinding.componentId(),
                                projectId,
                                reportedFinding.analyzerName(),
                                reportedFinding.referenceUrl()));
            }
        }

        // Determine which attributions are no longer applicable, and should be deleted.
        final var attributionIdsToDelete = new HashSet<Long>();
        for (final FindingDao.FindingAttribution existingAttribution : existingAttributions) {
            final var attributionKey = new FindingAttributionKey(
                    new FindingKey(existingAttribution.componentId(), existingAttribution.vulnDbId()),
                    existingAttribution.analyzerName());

            // NB: If an analyzer previously reported the finding,
            // and now failed, we cannot assume that the finding
            // is no longer reported. So keep it in that case.
            if (!reportedAttributionKeys.contains(attributionKey)
                    && !failedAnalyzers.contains(attributionKey.analyzerName())) {
                attributionIdsToDelete.add(existingAttribution.id());
            }
        }

        // Evaluate vulnerability policies, if there are any.
        // Only evaluate policies for active findings (i.e. those with >=1 attributions).
        final Map<Long, Set<Long>> vulnDbIdsByComponentId =
                computeActiveFindings(
                        existingAttributionsByFindingKey,
                        attributionIdsToDelete,
                        findingsToCreate,
                        createAttributionCommands);

        // Determine findings that became inactive. They exist in current attributions,
        // but are not in the set of active findings (i.e. all attributions were deleted).
        final Set<FindingKey> inactiveFindingKeys = existingAttributionsByFindingKey.keySet().stream()
                .filter(findingKey -> {
                    final Set<Long> activeVulnDbIds = vulnDbIdsByComponentId.get(findingKey.componentId());
                    return activeVulnDbIds == null || !activeVulnDbIds.contains(findingKey.vulnDbId());
                })
                .collect(Collectors.toSet());

        final Map<Long, Map<Long, VulnerabilityPolicy>> policyResults =
                evaluateVulnPolicies(projectId, vulnDbIdsByComponentId, activityContext);

        if (Thread.interrupted()) {
            throw new InterruptedException("Interrupted before reconciling findings transaction");
        }

        // Flush all computed changes to the database in a single transaction.
        // Note that this is done for both performance and idempotency reasons.
        // Since this activity may be retried, we cannot commit partial changes.
        useJdbiTransaction(handle -> {
            final var notificationSubjectDao = handle.attach(NotificationSubjectDao.class);
            final var findingDao = new FindingDao(handle);

            final List<FindingKey> createdFindingKeys = findingDao.createFindings(findingsToCreate);
            LOGGER.debug("Created {} new finding(s)", createdFindingKeys.size());

            // Reactivated findings are those scheduled for creation (because they had
            // no active attributions), but whose COMPONENTS_VULNERABILITIES row already
            // existed. createFindings uses ON CONFLICT DO NOTHING, so these are in
            // findingsToCreate but not in createdFindings.
            final var reactivatedFindingKeys = new HashSet<>(findingsToCreate);
            reactivatedFindingKeys.removeAll(new HashSet<>(createdFindingKeys));

            final int attributionsCreated = findingDao.createAttributions(createAttributionCommands);
            LOGGER.debug("Created {} new attribution(s)", attributionsCreated);

            final int attributionsDeleted = findingDao.deleteAttributions(attributionIdsToDelete);
            LOGGER.debug("Removed {} stale attribution(s)", attributionsDeleted);

            final List<Notification> auditChangeNotifications =
                    applyVulnPolicyResults(handle, projectId, policyResults, vulnDbIdsByComponentId);

            final var notifications = new ArrayList<>(auditChangeNotifications);
            notifications.addAll(createAnalyzerErrorNotifications(projectUuid, failedAnalyzers));
            notifications.addAll(
                    createNewVulnerabilityNotifications(
                            notificationSubjectDao,
                            Stream
                                    .concat(createdFindingKeys.stream(), reactivatedFindingKeys.stream())
                                    .collect(Collectors.toSet()),
                            arg.getAnalysisTrigger()));
            notifications.addAll(
                    createVulnerabilityRetractedNotifications(
                            notificationSubjectDao,
                            inactiveFindingKeys));
            if (arg.hasContextFileMetadata()) {
                final List<Long> newComponentIds = readNewComponentIds(arg.getContextFileMetadata());
                if (!newComponentIds.isEmpty()) {
                    notificationSubjectDao
                            .getForNewVulnerableDependencies(newComponentIds)
                            .stream()
                            .map(subject -> createNewVulnerableDependencyNotification(
                                    subject.getProject(),
                                    subject.getComponent(),
                                    subject.getVulnerabilitiesList()))
                            .forEach(notifications::add);
                }
            }

            LOGGER.debug("Updating project's last vuln analysis timestamp");
            handle.attach(ProjectDao.class).updateLastVulnAnalysis(projectUuid);

            LOGGER.debug("Emitting {} notification(s)", notifications.size());
            new JdbiNotificationEmitter(handle).emitAll(notifications);
        });
    }

    private List<Long> readNewComponentIds(FileMetadata contextFileMetadata) {
        try (final InputStream inputStream = fileStorage.get(contextFileMetadata)) {
            final VulnAnalysisWorkflowContext context = VulnAnalysisWorkflowContext.parseFrom(inputStream);
            return context.getNewComponentIdsList();
        } catch (Exception e) {
            LOGGER.warn("""
                    Failed to read context file; NEW_VULNERABLE_DEPENDENCY notifications \
                    will not be emitted""", e);
            return List.of();
        }
    }

    private static Map<Long, Set<Long>> computeActiveFindings(
            Map<FindingKey, List<FindingDao.FindingAttribution>> existingAttributionsByFindingKey,
            Set<Long> attributionIdsToDelete,
            Set<FindingKey> findingsToCreate,
            Set<FindingDao.CreateAttributionCommand> createAttributionCommands) {
        final var activeFindings = new HashMap<Long, Set<Long>>();

        // Consider existing findings as active if at least one
        // existing attribution is NOT scheduled for deletion.
        for (final var entry : existingAttributionsByFindingKey.entrySet()) {
            final FindingKey findingKey = entry.getKey();
            final List<FindingDao.FindingAttribution> existingAttributions = entry.getValue();

            final boolean allAttributionsDeleted = existingAttributions.stream()
                    .map(FindingDao.FindingAttribution::id)
                    .allMatch(attributionIdsToDelete::contains);
            if (!allAttributionsDeleted) {
                activeFindings
                        .computeIfAbsent(findingKey.componentId(), k -> new HashSet<>())
                        .add(findingKey.vulnDbId());
            }
        }

        // Findings that are scheduled for creation are inherently active.
        for (final FindingKey findingKey : findingsToCreate) {
            activeFindings
                    .computeIfAbsent(findingKey.componentId(), k -> new HashSet<>())
                    .add(findingKey.vulnDbId());
        }

        // Handle the case where a finding:
        //   * Was previously reported by analyzer A.
        //   * Is no longer reported by analyzer A (i.e. its attribution is in attributionIdsToDelete).
        //   * Is now reported by analyzer B.
        // Because the finding already existed, it won't be in findingsToCreate.
        // But an attribution for analyzer B is scheduled for creation,
        // which tells us that the finding is still active.
        for (final FindingDao.CreateAttributionCommand command : createAttributionCommands) {
            activeFindings
                    .computeIfAbsent(command.componentId(), k -> new HashSet<>())
                    .add(command.vulnDbId());
        }

        return activeFindings;
    }

    private Map<Long, Map<Long, VulnerabilityPolicy>> evaluateVulnPolicies(
            long projectId,
            Map<Long, Set<Long>> vulnIdsByComponentId,
            ActivityContext activityContext) {
        if (vulnIdsByComponentId.isEmpty()) {
            return Map.of();
        }

        final Map<Long, Map<Long, VulnerabilityPolicy>> evaluationResult;
        try {
            evaluationResult = vulnPolicyEvaluator.evaluateAll(
                    projectId,
                    vulnIdsByComponentId,
                    PolicyEvaluationDeadline.wrapping(activityContext::maybeHeartbeat, maxEvaluationDuration));
        } catch (PolicyEvaluationTimedOutException e) {
            LOGGER.error(
                    """
                            Vulnerability policy evaluation for project {} exceeded maximum duration of {}; \
                            skipping policy application. Findings reconciliation will continue. \
                            Verify that policies still hold.""",
                    projectId,
                    e.maxDuration());
            return Map.of();
        }
        if (evaluationResult.isEmpty()) {
            LOGGER.debug("Vulnerability policy evaluation did not yield any results");
            return Map.of();
        }

        // Policies with mode LOG do not require any database changes.
        // Log them now, and omit them from the result returned by this method.
        final var applicableResult = new HashMap<Long, Map<Long, VulnerabilityPolicy>>();
        for (final var entry : evaluationResult.entrySet()) {
            final long componentId = entry.getKey();
            final Map<Long, VulnerabilityPolicy> policyByVulnDbId = entry.getValue();

            for (final var vulnEntry : policyByVulnDbId.entrySet()) {
                final long vulnDbId = vulnEntry.getKey();
                final VulnerabilityPolicy policy = vulnEntry.getValue();

                if (policy.getOperationMode() == VulnerabilityPolicyOperation.LOG) {
                    LOGGER.info(
                            "Vulnerability policy '{}' matched for component {} and vulnerability {}",
                            policy.getName(),
                            componentId,
                            vulnDbId);
                    continue;
                }

                applicableResult
                        .computeIfAbsent(componentId, k -> new HashMap<>())
                        .put(vulnEntry.getKey(), policy);
            }
        }

        return applicableResult;
    }

    private List<Notification> applyVulnPolicyResults(
            Handle handle,
            long projectId,
            Map<Long, Map<Long, VulnerabilityPolicy>> policyResults,
            Map<Long, Set<Long>> activeFindings) {
        final var analysisDao = new AnalysisDao(handle);
        final var reconcileResults = new ArrayList<AnalysisReconciler.Result>();

        // Collect finding keys that have applicable policy results.
        final Set<FindingKey> policyFindingKeys = policyResults.entrySet().stream()
                .flatMap(entry -> {
                    final long componentId = entry.getKey();
                    return entry.getValue().keySet().stream()
                            .map(vulnDbId -> new FindingKey(componentId, vulnDbId));
                })
                .collect(Collectors.toSet());

        // Apply policies to findings that have matching policy results.
        if (!policyFindingKeys.isEmpty()) {
            final Map<FindingKey, Analysis> existingAnalysisByFindingKey =
                    analysisDao.getForProjectFindings(projectId, policyFindingKeys);
            LOGGER.debug("Found {} existing analyses for {} finding(s) with policy results",
                    existingAnalysisByFindingKey.size(), policyFindingKeys.size());

            for (final var componentEntry : policyResults.entrySet()) {
                final long componentId = componentEntry.getKey();
                final Map<Long, VulnerabilityPolicy> policyByVulnDbId = componentEntry.getValue();

                for (final var vulnEntry : policyByVulnDbId.entrySet()) {
                    final long vulnDbId = vulnEntry.getKey();
                    final VulnerabilityPolicy policy = vulnEntry.getValue();

                    final var findingKey = new FindingKey(componentId, vulnDbId);
                    final Analysis existingAnalysis = existingAnalysisByFindingKey.get(findingKey);
                    LOGGER.debug("Reconciling analysis for {}", findingKey);

                    final var analysisReconciler = new AnalysisReconciler(projectId, componentId, vulnDbId, existingAnalysis);
                    final AnalysisReconciler.Result reconcileResult = analysisReconciler.reconcile(policy);
                    if (reconcileResult != null) {
                        reconcileResults.add(reconcileResult);
                    }
                }
            }
        }

        // Reset stale analyses that were previously applied by a policy,
        // but whose corresponding finding no longer has a matching policy.
        // This may happen when policies are removed, or their conditions are modified.
        final Map<FindingKey, Analysis> staleAnalysisByFindingKey =
                analysisDao.getForProjectWithPolicyApplied(projectId, policyFindingKeys);
        for (final var entry : staleAnalysisByFindingKey.entrySet()) {
            final FindingKey findingKey = entry.getKey();
            final Analysis analysis = entry.getValue();

            final Set<Long> activeVulnIds = activeFindings.get(findingKey.componentId());
            if (activeVulnIds == null || !activeVulnIds.contains(findingKey.vulnDbId())) {
                continue;
            }

            LOGGER.debug("Un-applying stale policy analysis for {}", findingKey);
            final var reconciler = new AnalysisReconciler(projectId, findingKey.componentId(), findingKey.vulnDbId(), analysis);
            final AnalysisReconciler.Result unapplyResult = reconciler.reconcileForNoPolicy();
            if (unapplyResult != null) {
                reconcileResults.add(unapplyResult);
            }
        }

        if (reconcileResults.isEmpty()) {
            LOGGER.debug("All analyses are already in desired state");
            return List.of();
        }

        // Create or update analyses according to the reconciliation results.
        final List<MakeAnalysisCommand> makeAnalysisCommands =
                reconcileResults.stream()
                        .map(AnalysisReconciler.Result::makeAnalysisCommand)
                        .toList();
        final Map<FindingKey, Long> modifiedAnalysisIdByFindingKey = analysisDao.makeAnalyses(makeAnalysisCommands);
        LOGGER.debug("Modified {} analysis record(s)", modifiedAnalysisIdByFindingKey.size());

        // Populate the audit trail for analyses that have actually changed.
        final var createCommentCommands = new ArrayList<AnalysisDao.CreateCommentCommand>();
        for (final var reconcileResult : reconcileResults) {
            final Long analysisId = modifiedAnalysisIdByFindingKey.get(reconcileResult.findingKey());
            if (analysisId != null) {
                createCommentCommands.addAll(reconcileResult.createCommentCommands(analysisId));
            }
        }
        final int commentsCreated = analysisDao.createComments(createCommentCommands);
        LOGGER.debug("Created {} analysis comment(s)", commentsCreated);

        // Build notifications for analyses where state or suppression changed.
        final List<AnalysisReconciler.Result> auditChangeResults =
                reconcileResults.stream()
                        .filter(result -> result.analysisStateChanged() || result.suppressionChanged())
                        .toList();
        if (auditChangeResults.isEmpty()) {
            return List.of();
        }

        final List<GetProjectAuditChangeNotificationSubjectQuery> notificationSubjectQueries =
                auditChangeResults.stream()
                        .map(result -> new GetProjectAuditChangeNotificationSubjectQuery(
                                result.findingKey().componentId(),
                                result.findingKey().vulnDbId(),
                                result.makeAnalysisCommand().state(),
                                result.makeAnalysisCommand().suppressed()))
                        .toList();

        final var notificationSubjectDao = handle.attach(NotificationSubjectDao.class);
        final List<VulnerabilityAnalysisDecisionChangeSubject> subjects =
                notificationSubjectDao.getForProjectAuditChanges(notificationSubjectQueries);

        final var notifications = new ArrayList<Notification>(subjects.size());
        for (int i = 0; i < subjects.size(); i++) {
            final AnalysisReconciler.Result result = auditChangeResults.get(i);
            final VulnerabilityAnalysisDecisionChangeSubject subject = subjects.get(i);
            notifications.add(
                    createVulnerabilityAnalysisDecisionChangeNotification(
                            subject.getProject(),
                            subject.getComponent(),
                            subject.getVulnerability(),
                            subject.getAnalysis(),
                            result.analysisStateChanged(),
                            result.suppressionChanged()));
        }

        return notifications;
    }

    private List<Notification> createAnalyzerErrorNotifications(UUID projectUuid, Collection<String> analyzerNames) {
        if (analyzerNames.isEmpty()) {
            return List.of();
        }

        return analyzerNames.stream()
                .map(analyzerName -> createAnalyzerErrorNotification(
                        "Vulnerability analyzer '%s' failed for project '%s'".formatted(
                                analyzerName, projectUuid)))
                .toList();

    }

    private List<Notification> createNewVulnerabilityNotifications(
            NotificationSubjectDao dao,
            Collection<FindingKey> findingKeys,
            AnalysisTrigger analysisTrigger) {
        if (findingKeys.isEmpty()) {
            return List.of();
        }

        final var componentIds = new ArrayList<Long>(findingKeys.size());
        final var vulnDbIds = new ArrayList<Long>(findingKeys.size());

        findingKeys.forEach(findingKey -> {
            componentIds.add(findingKey.componentId());
            vulnDbIds.add(findingKey.vulnDbId());
        });

        return dao
                .getForNewVulnerabilities(componentIds, vulnDbIds)
                .stream()
                .map(subject -> createNewVulnerabilityNotification(
                        subject.getProject(),
                        subject.getComponent(),
                        subject.getVulnerability(),
                        convertAnalysisTrigger(analysisTrigger)))
                .toList();
    }

    private List<Notification> createVulnerabilityRetractedNotifications(
            NotificationSubjectDao dao,
            Collection<FindingKey> findingKeys) {
        if (findingKeys.isEmpty()) {
            return List.of();
        }

        final var componentIds = new ArrayList<Long>(findingKeys.size());
        final var vulnDbIds = new ArrayList<Long>(findingKeys.size());

        findingKeys.forEach(findingKey -> {
            componentIds.add(findingKey.componentId());
            vulnDbIds.add(findingKey.vulnDbId());
        });

        return dao
                .getForNewVulnerabilities(componentIds, vulnDbIds)
                .stream()
                .map(subject -> createVulnerabilityRetractedNotification(
                        subject.getProject(),
                        subject.getComponent(),
                        subject.getVulnerability()))
                .toList();
    }

    private static org.dependencytrack.notification.proto.v1.AnalysisTrigger convertAnalysisTrigger(AnalysisTrigger trigger) {
        return switch (trigger) {
            case ANALYSIS_TRIGGER_BOM_UPLOAD ->
                    org.dependencytrack.notification.proto.v1.AnalysisTrigger.ANALYSIS_TRIGGER_BOM_UPLOAD;
            case ANALYSIS_TRIGGER_SCHEDULE ->
                    org.dependencytrack.notification.proto.v1.AnalysisTrigger.ANALYSIS_TRIGGER_SCHEDULE;
            case ANALYSIS_TRIGGER_MANUAL ->
                    org.dependencytrack.notification.proto.v1.AnalysisTrigger.ANALYSIS_TRIGGER_MANUAL;
            case ANALYSIS_TRIGGER_UNSPECIFIED ->
                    org.dependencytrack.notification.proto.v1.AnalysisTrigger.ANALYSIS_TRIGGER_UNSPECIFIED;
            case UNRECOGNIZED -> org.dependencytrack.notification.proto.v1.AnalysisTrigger.UNRECOGNIZED;
        };
    }

}
