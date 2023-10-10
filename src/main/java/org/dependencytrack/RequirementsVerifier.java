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
package org.dependencytrack;

import alpine.Config;
import alpine.common.logging.Logger;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.exception.RequirementsException;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class RequirementsVerifier implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(RequirementsVerifier.class);
    private static final boolean systemRequirementCheckEnabled = Config.getInstance().getPropertyAsBoolean(ConfigKey.SYSTEM_REQUIREMENT_CHECK_ENABLED);
    private static boolean failedValidation = false;

    private static synchronized void setFailedValidation(boolean value) {
        failedValidation = value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing requirements verifier");
        if (Runtime.getRuntime().maxMemory()/1024/1024 <= 3584) {
            if (systemRequirementCheckEnabled) {
                setFailedValidation(true);
                // too complicated to calculate (Eden, Survivor, Tenured) and different type names between Java versions.
                // Therefore, safely assume anything above 3.5GB available max memory is likely to be 4GB or higher.
                final String message = "Dependency-Track requires a minimum of 4GB RAM (heap). Cannot continue. To fix, specify -Xmx4G (or higher) when executing Java.";
                LOGGER.error(message);
                throw new RequirementsException(message);
            } else {
                final String message = "Dependency-Track requires a minimum of 4GB RAM (heap). We highly recommand to use 4GB RAM. Dependency-Track will continue to start, but may not function properly. https://docs.dependencytrack.org/getting-started/deploy-docker/#container-requirements-api-server";
                LOGGER.warn(message);
            }
        }
        if (Runtime.getRuntime().availableProcessors() < 2) {
            if (systemRequirementCheckEnabled) {
                setFailedValidation(true);
                final String message = "Dependency-Track requires a minimum of 2 CPU cores. Cannot continue. To fix, specify -Xmx4G (or higher) when executing Java.";
                LOGGER.error(message);
                throw new RequirementsException(message);
            } else {
                final String message = "Dependency-Track requires a minimum of 2 CPU cores. We highly recommand to use 2 CPU cores. Dependency-Track will continue to start, but may not function properly. https://docs.dependencytrack.org/getting-started/deploy-docker/#container-requirements-api-server";
                LOGGER.warn(message);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        /* Intentionally blank to satisfy interface */
    }

    public static boolean failedValidation() {
        return failedValidation;
    }
}
