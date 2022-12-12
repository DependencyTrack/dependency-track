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
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import org.dependencytrack.event.ClearComponentAnalysisCacheEvent;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.persistence.QueryManager;

import java.time.Instant;
import java.util.Date;

/**
 * Subscriber task that clears the ComponentAnalysisCache.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
public class ClearComponentAnalysisCacheTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(ClearComponentAnalysisCacheTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof ClearComponentAnalysisCacheEvent) {
            LOGGER.info("Clearing ComponentAnalysisCache");
            try (QueryManager qm = new QueryManager()) {
                ConfigProperty cacheClearPeriod = qm.getConfigProperty(ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getGroupName(), ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyName());
                long cacheValidityPeriodMs = Long.parseLong(cacheClearPeriod.getPropertyValue());
                Date threshold = Date.from(Instant.now().minusMillis(cacheValidityPeriodMs));
                qm.clearComponentAnalysisCache(threshold);
            } catch (Exception ex) {
                LOGGER.error("An unknown error occurred while clearing component analysis cache", ex);
            }
            LOGGER.info("Complete");
        }
    }
}
