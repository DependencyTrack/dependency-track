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
package org.dependencytrack;

import alpine.logging.Logger;
import alpine.util.JavaVersion;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class RequirementsVerifier implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(RequirementsVerifier.class);
    private static boolean failedValidation = false;

    /**
     * {@inheritDoc}
     */
    public void contextInitialized(ServletContextEvent event) {
        final JavaVersion javaVersion = new JavaVersion();
        if (javaVersion.getMajor() != 8 || javaVersion.getUpdate() < 161) {
            failedValidation = true;
            final String message = "Dependency-Track requires Java 8 with a minimum update of 162 or higher. Cannot continue.";
            LOGGER.error("Using Java version: " + javaVersion.toString());
            LOGGER.error(message);
            throw new RuntimeException(message);
        }
        if (Runtime.getRuntime().maxMemory()/1024/1024 <= 3584) {
            failedValidation = true;
            // too complicated to calculate (Eden, Survivor, Tenured) and different type names between Java versions.
            // Therefore, safely assume anything above 3.5GB available max memory is likely to be 4GB or higher.
            final String message = "Dependency-Track requires a minimum of 4GB RAM (heap). Cannot continue. To fix, specify -Xmx4G (or higher) when executing Java.";
            LOGGER.error(message);
            throw new RuntimeException(message);
        }
        if (Runtime.getRuntime().availableProcessors() < 2) {
            failedValidation = true;
            final String message = "Dependency-Track requires a minimum of 2 CPU cores. Cannot continue.";
            LOGGER.error(message);
            throw new RuntimeException(message);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void contextDestroyed(ServletContextEvent event) {
        /* Intentionally blank to satisfy interface */
    }

    public static boolean failedValidation() {
        return failedValidation;
    }
}
