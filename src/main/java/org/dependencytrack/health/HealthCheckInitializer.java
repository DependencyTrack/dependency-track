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
package org.dependencytrack.health;

import alpine.common.logging.Logger;
import alpine.server.health.HealthCheckRegistry;
import alpine.server.health.checks.DatabaseHealthCheck;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class HealthCheckInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(HealthCheckInitializer.class);

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Registering health checks");
        HealthCheckRegistry.getInstance().register("database", new DatabaseHealthCheck());
    }

}
