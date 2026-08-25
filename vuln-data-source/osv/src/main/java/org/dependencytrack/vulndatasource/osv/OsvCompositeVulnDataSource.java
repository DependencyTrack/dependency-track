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

import java.util.List;
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

    OsvCompositeVulnDataSource(
            final List<OsvVulnDataSource> dataSources) {
        this.dataSources = requireNonNull(dataSources, "dataSources must not be null");
    }


    @Override
    public boolean hasNext() {
        while (currentDataSourceIndex < dataSources.size()) {
            if (dataSources.get(currentDataSourceIndex).hasNext()) {
                return true;
            }
            currentDataSourceIndex ++;
        }
        return false;
    }

    @Override
    public Bom next() {
        if (currentDataSourceIndex >= dataSources.size()) {
            throw new NoSuchElementException();
        }
        currentDataSource = dataSources.get(currentDataSourceIndex);
        return currentDataSource.next();
    }

    @Override
    public void markProcessed(final Bom bom) {
        if (currentDataSource == null) {
            throw new IllegalStateException("No current data source to mark processed");
        }
        currentDataSource.markProcessed(bom);
    }

    @Override
    public void close() {
        for (final var dataSource : dataSources) {
            try {
                dataSource.close();
            } catch (final Exception e) {
                LOGGER.warn("Failed to close data source: {}", dataSource, e);
            }
        }
    }

    List<OsvVulnDataSource> getDataSources() {
        return dataSources;
    }
}