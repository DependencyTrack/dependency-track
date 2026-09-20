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
package org.dependencytrack.vulndatasource;

import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.dependencytrack.common.MdcScope;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
import org.dependencytrack.persistence.jdbi.VulnerabilityAliasDao;
import org.dependencytrack.persistence.jdbi.VulnerabilitySyncDao;
import org.dependencytrack.persistence.jdbi.VulnerableSoftwareDao;
import org.dependencytrack.plugin.runtime.NoSuchExtensionException;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.MirrorVulnDataSourceArg;
import org.dependencytrack.util.VulnerabilityUtil;
import org.dependencytrack.vulnanalysis.VulnerabilityUpdatePolicy;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.dependencytrack.common.MdcKeys.MDC_VULN_DATA_SOURCE_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_ID;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_SOURCE;
import static org.dependencytrack.parser.dependencytrack.BovModelConverter.distinctIgnoringDatastoreIdentity;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/**
 * @since 5.0.0
 */
@ActivitySpec(name = "mirror-vuln-data-source")
public final class MirrorVulnDataSourceActivity implements Activity<MirrorVulnDataSourceArg, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(MirrorVulnDataSourceActivity.class);
    private static final Duration HEARTBEAT_LOG_INTERVAL = Duration.ofSeconds(30);
    private static final int BATCH_SIZE = 100;
    private static final int BATCH_MAX_AFFECTED_VERSIONS = 25_000;

    private final PluginManager pluginManager;

    public MirrorVulnDataSourceActivity(PluginManager pluginManager) {
        this.pluginManager = pluginManager;
    }

    @Override
    public @Nullable Void execute(ActivityContext ctx, @Nullable MirrorVulnDataSourceArg arg) throws Exception {
        if (arg == null || arg.getDataSourceName().isEmpty()) {
            throw new TerminalApplicationFailureException("No argument or data source name provided");
        }

        final var source = Vulnerability.Source.ofName(arg.getSourceName());
        if (source == null) {
            throw new TerminalApplicationFailureException("Invalid source name: %s".formatted(arg.getSourceName()));
        }

        final VulnDataSourceFactory dataSourceFactory;
        try {
            dataSourceFactory = pluginManager.getFactory(VulnDataSource.class, arg.getDataSourceName());
        } catch (NoSuchExtensionException e) {
            throw new TerminalApplicationFailureException(
                    "No extension found for data source: %s".formatted(arg.getDataSourceName()), e);
        }

        if (!dataSourceFactory.isDataSourceEnabled()) {
            throw new TerminalApplicationFailureException(
                    "Data source %s is not enabled".formatted(arg.getDataSourceName()));
        }

        final var updatePolicy = new VulnerabilityUpdatePolicy(pluginManager);

        try (var _ = new MdcScope(Map.of(MDC_VULN_DATA_SOURCE_NAME, arg.getDataSourceName()))) {
            LOGGER.info("Starting mirror");
            final long startTimeNs = System.nanoTime();
            long lastHeartbeatNs = startTimeNs;
            int vulnsProcessed = 0;

            final VulnDataSource dataSource = dataSourceFactory.create();

            // NB: Give the data source the chance to persist its pending state
            // when the activity got interrupted. That requires temporarily popping
            // the interrupt flag from the thread before invoking close() on it.
            try (var _ = (Closeable) () -> closeUninterruptibly(dataSource)) {
                final var bovBatch = new ArrayList<Bom>(BATCH_SIZE);
                int affectedVersionsInBatch = 0;

                while (dataSource.hasNext()) {
                    if (Thread.interrupted()) {
                        throw new InterruptedException("Interrupted before all vulnerabilities could be consumed");
                    }

                    final Bom bov = dataSource.next();
                    bovBatch.add(bov);
                    affectedVersionsInBatch += affectedVersionCount(bov);

                    if (bovBatch.size() == BATCH_SIZE
                            // NB: A single vulnerability can have thousands of affected versions.
                            // Limiting batch sizes by vulnerability count alone is not sufficient.
                            || affectedVersionsInBatch >= BATCH_MAX_AFFECTED_VERSIONS) {
                        processBatch(dataSource, bovBatch, source, arg.getDataSourceName(), updatePolicy);
                        vulnsProcessed += bovBatch.size();
                        bovBatch.clear();
                        affectedVersionsInBatch = 0;
                        if (System.nanoTime() - lastHeartbeatNs >= HEARTBEAT_LOG_INTERVAL.toNanos()) {
                            LOGGER.info("Processed {} vulnerabilities so far", vulnsProcessed);
                            lastHeartbeatNs = System.nanoTime();
                        }
                    }
                }

                if (!bovBatch.isEmpty()) {
                    processBatch(dataSource, bovBatch, source, arg.getDataSourceName(), updatePolicy);
                    vulnsProcessed += bovBatch.size();
                    bovBatch.clear();
                }
            }

            LOGGER.info(
                    "Completed mirror; processed {} vulnerabilities in {}",
                    vulnsProcessed,
                    Duration.ofNanos(System.nanoTime() - startTimeNs));
        }

        return null;
    }

    private static void processBatch(
            VulnDataSource dataSource,
            Collection<Bom> bovs,
            Vulnerability.Source source,
            String dataSourceName,
            VulnerabilityUpdatePolicy updatePolicy) {
        LOGGER.debug("Processing batch of {} vulnerabilities", bovs.size());

        final var vulnByKey = new LinkedHashMap<VulnerabilityKey, Vulnerability>(bovs.size());
        final var vsListByVulnKey = new HashMap<VulnerabilityKey, List<VulnerableSoftware>>(bovs.size());
        final var aliasesByVulnKey = new LinkedHashMap<VulnerabilityKey, Set<VulnerabilityKey>>(bovs.size());

        for (final Bom bov : bovs) {
            if (bov.getVulnerabilitiesCount() == 0) {
                LOGGER.warn("Encountered record with no vulnerabilities; Skipping");
                continue;
            }

            if (bov.getVulnerabilitiesCount() > 1) {
                LOGGER.warn("Encountered record with more than one vulnerability; Skipping");
                continue;
            }

            final Vulnerability vuln;
            final List<VulnerableSoftware> vsList;
            try (var _ = new MdcScope(Map.ofEntries(
                    Map.entry(MDC_VULN_ID, bov.getVulnerabilities(0).getId()),
                    Map.entry(
                            MDC_VULN_SOURCE,
                            bov.getVulnerabilities(0).getSource().getName())))) {
                vuln = BovModelConverter.convert(bov, bov.getVulnerabilities(0), true);
                vsList = BovModelConverter.extractVulnerableSoftware(bov);
            }

            final var vulnKey = new VulnerabilityKey(vuln.getVulnId(), vuln.getSource());
            vulnByKey.put(vulnKey, vuln);

            // A batch can contain the same vulnerability more than once.
            // OSV for example publishes an advisory under every ecosystem it affects.
            // Merge rather than overwrite, since synchronization treats the list as the
            // complete set of software reported by the source.
            vsListByVulnKey.merge(
                    vulnKey,
                    vsList,
                    (vsListA, vsListB) -> Stream.concat(vsListA.stream(), vsListB.stream())
                            .filter(distinctIgnoringDatastoreIdentity())
                            .toList());

            final Set<VulnerabilityKey> aliasKeys = VulnerabilityUtil.extractAliasKeys(vuln.getAliases(), vulnKey);
            aliasesByVulnKey.put(vulnKey, aliasKeys);
        }

        if (!vulnByKey.isEmpty()) {
            useJdbiTransaction(handle -> {
                final var vulnerabilityDao = new VulnerabilitySyncDao(handle);
                final Map<VulnerabilityKey, Long> existingVulnIdByKey =
                        vulnerabilityDao.getIdsByKey(vulnByKey.keySet());

                final var syncableVulns = new ArrayList<Vulnerability>(vulnByKey.size());
                for (final Map.Entry<VulnerabilityKey, Vulnerability> entry : vulnByKey.entrySet()) {
                    final Vulnerability vuln = entry.getValue();
                    if (!updatePolicy.isUpdatableByDataSource(
                            vuln.getSource(), dataSourceName, existingVulnIdByKey.containsKey(entry.getKey()))) {
                        LOGGER.debug(
                                "Skipping vulnerability {} from source {}: authoritative source is enabled",
                                vuln.getVulnId(),
                                vuln.getSource());
                        continue;
                    }

                    syncableVulns.add(vuln);
                }

                final Map<VulnerabilityKey, Long> vulnIdByKey = vulnerabilityDao.upsertAll(
                        syncableVulns, /* canUpdatePredicate */ _ -> true, /* requireNewerUpdated */ false);
                new VulnerableSoftwareDao(handle).syncAll(source, vulnIdByKey, vsListByVulnKey);

                if (!aliasesByVulnKey.isEmpty()) {
                    new VulnerabilityAliasDao(handle)
                            .syncAssertions("vuln-data-source:" + dataSourceName, aliasesByVulnKey);
                }
            });
        }

        for (final Bom bov : bovs) {
            dataSource.markProcessed(bov);
        }
    }

    private static int affectedVersionCount(Bom bov) {
        if (bov.getVulnerabilitiesCount() == 0) {
            return 0;
        }

        int count = 0;
        for (final VulnerabilityAffects affects : bov.getVulnerabilities(0).getAffectsList()) {
            count += affects.getVersionsCount();
        }

        return count;
    }

    private static void closeUninterruptibly(VulnDataSource dataSource) {
        final boolean interrupted = Thread.interrupted();
        try {
            dataSource.close();
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
