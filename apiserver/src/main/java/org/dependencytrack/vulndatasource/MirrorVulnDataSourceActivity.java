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

import com.google.protobuf.util.Timestamps;
import org.cyclonedx.proto.v1_7.Bom;
import org.dependencytrack.common.MdcScope;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.VulnerabilityAliasDao;
import org.dependencytrack.plugin.runtime.NoSuchExtensionException;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.MirrorVulnDataSourceArg;
import org.dependencytrack.util.VulnerabilityUtil;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.datanucleus.PropertyNames.PROPERTY_MANAGE_RELATIONSHIPS;
import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_ID;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_SOURCE;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/**
 * @since 5.7.0
 */
@ActivitySpec(name = "mirror-vuln-data-source")
public final class MirrorVulnDataSourceActivity implements Activity<MirrorVulnDataSourceArg, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(MirrorVulnDataSourceActivity.class);

    private final PluginManager pluginManager;

    public MirrorVulnDataSourceActivity(PluginManager pluginManager) {
        this.pluginManager = pluginManager;
    }

    @Override
    public @Nullable Void execute(
            ActivityContext ctx,
            @Nullable MirrorVulnDataSourceArg arg) throws Exception {
        if (arg == null || arg.getDataSourceName().isEmpty()) {
            throw new TerminalApplicationFailureException("No argument or data source name provided");
        }

        final Vulnerability.Source source;
        try {
            source = Vulnerability.Source.valueOf(arg.getSourceName());
        } catch (IllegalArgumentException e) {
            throw new TerminalApplicationFailureException(
                    "Invalid source name: %s".formatted(arg.getSourceName()));
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

        try (final VulnDataSource dataSource = dataSourceFactory.create()) {
            final var bovBatch = new ArrayList<Bom>(25);
            while (dataSource.hasNext()) {
                if (Thread.interrupted()) {
                    throw new InterruptedException("Interrupted before all BOVs could be consumed");
                }
                ctx.maybeHeartbeat();

                final Bom bov = dataSource.next();
                if (!bov.getVulnerabilities(0).hasRejected()) {
                    bovBatch.add(bov);
                    if (bovBatch.size() == 25) {
                        processBatch(dataSource, bovBatch, source, arg.getDataSourceName());
                        bovBatch.clear();
                    }
                } else {
                    LOGGER.warn(
                            "Skipping vulnerability {} rejected at {}",
                            bov.getVulnerabilities(0).getId(),
                            Timestamps.toString(bov.getVulnerabilities(0).getRejected()));
                }
            }

            if (!bovBatch.isEmpty()) {
                ctx.maybeHeartbeat();
                processBatch(dataSource, bovBatch, source, arg.getDataSourceName());
                bovBatch.clear();
            }
        }

        return null;
    }

    private static void processBatch(
            VulnDataSource dataSource,
            Collection<Bom> bovs,
            Vulnerability.Source source,
            String dataSourceName) {
        LOGGER.debug("Processing batch of {} BOVs", bovs.size());

        final var vulns = new ArrayList<Vulnerability>(bovs.size());
        final var vsListByVulnId = new HashMap<String, List<VulnerableSoftware>>(bovs.size());
        final var aliasesByVuln = new LinkedHashMap<VulnerabilityKey, Set<VulnerabilityKey>>(bovs.size());

        for (final Bom bov : bovs) {
            if (bov.getVulnerabilitiesCount() == 0) {
                LOGGER.warn("BOV contains no vulnerabilities; Skipping");
                continue;
            }

            if (bov.getVulnerabilitiesCount() > 1) {
                LOGGER.warn("BOV contains more than one vulnerability; Skipping");
                continue;
            }

            final Vulnerability vuln;
            final List<VulnerableSoftware> vsList;
            try (var ignored = new MdcScope(Map.ofEntries(
                    Map.entry(MDC_VULN_ID, bov.getVulnerabilities(0).getId()),
                    Map.entry(MDC_VULN_SOURCE, bov.getVulnerabilities(0).getSource().getName())))) {
                vuln = BovModelConverter.convert(bov, bov.getVulnerabilities(0), true);
                vsList = BovModelConverter.extractVulnerableSoftware(bov);
            }

            vulns.add(vuln);
            vsListByVulnId.put(vuln.getVulnId(), vsList);

            final var vulnKey = new VulnerabilityKey(vuln.getVulnId(), vuln.getSource());
            final Set<VulnerabilityKey> aliasKeys = VulnerabilityUtil.extractAliasKeys(vuln.getAliases(), vulnKey);
            aliasesByVuln.put(vulnKey, aliasKeys);
        }

        try (final var qm = new QueryManager()) {
            // Disable managed relationships to avoid excessive N+1 queries during VulnerableSoftware synchronization.
            //
            //   "For an M-N bidirectional relation, at persist you MUST set one side and the other side will
            //   be populated at commit/flush to make them consistent."
            //   https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#managed_relationships
            //
            // The "consistent" is referring to in-memory state, NOT database records.
            // We don't need a fully consistent object graph here, in fact it's actively detrimental.
            qm.getPersistenceManager().setProperty(PROPERTY_MANAGE_RELATIONSHIPS, "false");
            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");

            qm.runInTransaction(() -> {
                for (final Vulnerability vuln : vulns) {
                    LOGGER.debug("Synchronizing vulnerability {}", vuln.getVulnId());
                    final Vulnerability existingVuln = qm.getVulnerabilityByVulnId(vuln.getSource(), vuln.getVulnId());
                    final Vulnerability persistentVuln = existingVuln == null
                            ? qm.createVulnerability(vuln)
                            : qm.updateVulnerability(existingVuln, vuln);
                    final List<VulnerableSoftware> vsList = vsListByVulnId.get(persistentVuln.getVulnId());
                    qm.synchronizeVulnerableSoftware(persistentVuln, vsList, source);
                }
            });

            if (!aliasesByVuln.isEmpty()) {
                useJdbiTransaction(handle -> new VulnerabilityAliasDao(handle)
                        .syncAssertions("vuln-data-source:" + dataSourceName, aliasesByVuln));
            }
        }

        for (final Bom bov : bovs) {
            dataSource.markProcessed(bov);
        }
    }

}
