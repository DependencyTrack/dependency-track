/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.scanners;

import alpine.logging.Logger;
import alpine.model.ConfigProperty;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import alpine.resources.OrderDirection;
import alpine.resources.Pagination;
import alpine.util.BooleanUtil;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.persistence.QueryManager;

/**
 * A base class that has logic common or useful to all classes that extend it.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public abstract class BaseComponentAnalyzerTask implements ScanTask {

    private final int paginationLimit;
    private final int throttleDelay;

    protected BaseComponentAnalyzerTask() {
        this.paginationLimit = 1000;
        this.throttleDelay = 0;
    }

    protected BaseComponentAnalyzerTask(int paginationLimit) {
        this.paginationLimit = paginationLimit;
        this.throttleDelay = 0;
    }

    protected BaseComponentAnalyzerTask(int paginationLimit, int throttleSeconds) {
        this.paginationLimit = paginationLimit;
        this.throttleDelay = throttleSeconds > 0 ? throttleSeconds * 1000 : 0;
    }

    protected boolean isEnabled(ConfigPropertyConstants configPropertyConstants) {
        try (QueryManager qm = new QueryManager()) {
            ConfigProperty property = qm.getConfigProperty(
                    configPropertyConstants.getGroupName(), configPropertyConstants.getPropertyName()
            );
            if (ConfigProperty.PropertyType.BOOLEAN == property.getPropertyType()) {
                return BooleanUtil.valueOf(property.getPropertyValue());
            }
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    public void analyze() {
        Logger logger = Logger.getLogger(this.getClass()); // We don't want the base class to be the logger
        logger.info("Analyzing portfolio");
        final AlpineRequest alpineRequest = new AlpineRequest(
                null,
                new Pagination(Pagination.Strategy.OFFSET, 0, paginationLimit),
                null,
                "id",
                OrderDirection.ASCENDING
        );
        try (QueryManager qm = new QueryManager(alpineRequest)) {
            final long total = qm.getCount(Component.class);
            long count = 0;
            while (count < total) {
                final PaginatedResult result = qm.getComponents();
                analyze(result.getList(Component.class));
                count += result.getObjects().size();
                qm.advancePagination();
                doThrottleDelay();
            }
        }
        logger.info("Portfolio analysis complete");
    }

    protected void doThrottleDelay() {
        Logger logger = Logger.getLogger(this.getClass()); // We don't want the base class to be the logger
        if (throttleDelay > 0) {
            try {
                Thread.sleep(throttleDelay);
            } catch (InterruptedException e) {
                logger.error("An error occurred while throttling the scanner.", e);
            }
        }
    }

}
