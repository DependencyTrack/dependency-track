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
package org.dependencytrack.search;

import alpine.common.logging.Logger;
import org.dependencytrack.RequirementsVerifier;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.util.Arrays;

/**
 * Build lucene indexes if needed.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class IndexSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(IndexSubsystemInitializer.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Building lucene indexes if required");

        if (RequirementsVerifier.failedValidation()) {
            return;
        }

        IndexManager.ensureIndexesExists();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Closing search indexes");

        Arrays.stream(IndexManager.IndexType.values())
                .map(IndexManager.IndexType::getClazz)
                .map(IndexManagerFactory::getIndexManager)
                .forEach(IndexManager::close);
    }
}
