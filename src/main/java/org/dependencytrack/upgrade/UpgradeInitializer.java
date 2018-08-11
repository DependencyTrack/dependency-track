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
package org.dependencytrack.upgrade;

import alpine.logging.Logger;
import alpine.upgrade.UpgradeException;
import alpine.upgrade.UpgradeExecutor;
import org.dependencytrack.RequirementsVerifier;
import org.dependencytrack.persistence.QueryManager;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class UpgradeInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(UpgradeInitializer.class);

    /**
     * {@inheritDoc}
     */
    public void contextInitialized(ServletContextEvent event) {
        if (RequirementsVerifier.failedValidation()) {
            return;
        }
        QueryManager qm = new QueryManager();
        UpgradeExecutor executor = new UpgradeExecutor(qm);

        try {
            executor.executeUpgrades(UpgradeItems.getUpgradeItems());
        }
        catch (UpgradeException e) {
            LOGGER.error("An error occurred performing upgrade processing. " + e.getMessage());
        }
    }

    /**
     * {@inheritDoc}
     */
    public void contextDestroyed(ServletContextEvent event) {
        /* Intentionally blank to satisfy interface */
    }

}