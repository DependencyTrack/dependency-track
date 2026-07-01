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
package org.dependencytrack.kevdatasource;

import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.kevdatasource.api.KevDataSourceFactory;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.persistence.jdbi.KevDao;
import org.dependencytrack.plugin.runtime.NoSuchExtensionException;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.MirrorKevDataSourceArg;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import static org.dependencytrack.common.MdcKeys.MDC_KEV_DATA_SOURCE_NAME;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/// @since 5.1.0
@ActivitySpec(name = "mirror-kev-data-source")
public final class MirrorKevDataSourceActivity implements Activity<MirrorKevDataSourceArg, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(MirrorKevDataSourceActivity.class);
    private static final int BATCH_SIZE = 1000;

    private final PluginManager pluginManager;

    public MirrorKevDataSourceActivity(PluginManager pluginManager) {
        this.pluginManager = pluginManager;
    }

    @Override
    public @Nullable Void execute(
            ActivityContext ctx,
            @Nullable MirrorKevDataSourceArg arg) throws Exception {
        if (arg == null || arg.getDataSourceName().isEmpty()) {
            throw new TerminalApplicationFailureException("No argument or data source name provided");
        }
        final String dataSourceName = arg.getDataSourceName();

        final KevDataSourceFactory factory;
        try {
            factory = pluginManager.getFactory(KevDataSource.class, dataSourceName);
        } catch (NoSuchExtensionException e) {
            throw new TerminalApplicationFailureException(
                    "No extension found for KEV data source: %s".formatted(dataSourceName), e);
        }

        if (!factory.isEnabled()) {
            throw new TerminalApplicationFailureException(
                    "KEV data source %s is not enabled".formatted(dataSourceName));
        }

        try (var _ = MDC.putCloseable(MDC_KEV_DATA_SOURCE_NAME, dataSourceName)) {
            LOGGER.info("Mirroring KEV data source");

            final var batch = new ArrayList<KevAssertion>(BATCH_SIZE);
            final var vulnKeysSeen = new HashSet<VulnerabilityKey>();
            int processed = 0;

            try (final KevDataSource dataSource = factory.create()) {
                while (dataSource.hasNext()) {
                    if (Thread.interrupted()) {
                        throw new InterruptedException(
                                "Interrupted before all KEV assertions could be consumed");
                    }
                    ctx.maybeHeartbeat();

                    final KevAssertion assertion = dataSource.next();
                    batch.add(assertion);
                    vulnKeysSeen.add(new VulnerabilityKey(assertion.vulnId(), assertion.vulnSource()));

                    if (batch.size() == BATCH_SIZE) {
                        upsertBatch(dataSourceName, batch);
                        processed += batch.size();
                        batch.clear();
                    }
                }
                if (!batch.isEmpty()) {
                    upsertBatch(dataSourceName, batch);
                    processed += batch.size();
                }
            }

            useJdbiTransaction(handle -> {
                final var dao = handle.attach(KevDao.class);
                if (vulnKeysSeen.isEmpty() && dao.hasAssertions(dataSourceName)) {
                    LOGGER.warn("""
                            Refusing to delete all KEV assertions: the source reported \
                            zero assertions, which is treated as an anomaly; existing data left intact.""");
                    return;
                }

                dao.deleteStale(dataSourceName, vulnKeysSeen);
            });

            LOGGER.info("Mirrored {} KEV assertion(s)", processed);
        }

        return null;
    }

    private static void upsertBatch(String asserter, List<KevAssertion> batch) {
        useJdbiTransaction(handle -> handle.attach(KevDao.class).upsertBatch(asserter, batch));
    }

}
