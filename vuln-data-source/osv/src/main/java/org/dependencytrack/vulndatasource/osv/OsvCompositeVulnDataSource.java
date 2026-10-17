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
package org.dependencytrack.vulndatasource.osv;

import org.cyclonedx.proto.v1_7.Bom;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class OsvCompositeVulnDataSource implements VulnDataSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(OsvCompositeVulnDataSource.class);
    private final List<OsvVulnDataSource> dataSources;
    private @Nullable OsvVulnDataSource currentDataSource;
    private int currentDataSourceIndex;

    /**
     * Tracks the originating data source for a Bom instance so markProcessed can be
     * delegated to the producer even if currentDataSource has moved on.
     */
    private final Map<Bom, OsvVulnDataSource> originMap = Collections.synchronizedMap(new IdentityHashMap<>());

    OsvCompositeVulnDataSource(final List<OsvVulnDataSource> dataSources) {
        this.dataSources = requireNonNull(dataSources, "dataSources must not be null");
    }

    @Override
    public boolean hasNext() {
        while (currentDataSourceIndex < dataSources.size()) {
            if (dataSources.get(currentDataSourceIndex).hasNext()) {
                return true;
            }
            currentDataSourceIndex++;
        }
        return false;
    }

    @Override
    public Bom next() {
        if (currentDataSourceIndex >= dataSources.size()) {
            throw new NoSuchElementException();
        }
        currentDataSource = dataSources.get(currentDataSourceIndex);
        try (final var _ = MDC.putCloseable("osvSource", currentDataSource.getDataSourceName())) {
            final Bom bom = currentDataSource.next();
            originMap.put(bom, currentDataSource);
            return bom;
        }
    }

    @Override
    public void markProcessed(final Bom bom) {
        final var origin = originMap.remove(bom);
        final var target = origin != null ? origin : currentDataSource;
        if (target == null) {
            throw new IllegalStateException("No data source available to mark processed");
        }
        try (final var _ = MDC.putCloseable("osvSource", target.getDataSourceName())) {
            target.markProcessed(bom);
        }
    }

    @Override
    public void close() {
        for (final var dataSource : dataSources) {
            try {
                dataSource.close();
            } catch (final Exception e) {
                LOGGER.warn("Failed to close data source: {}", dataSource.getDataSourceName(), e);
            }
        }
    }

    List<OsvVulnDataSource> getDataSources() {
        return dataSources;
    }
}
