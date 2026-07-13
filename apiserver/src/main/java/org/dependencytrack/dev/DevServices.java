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
package org.dependencytrack.dev;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.dependencytrack.common.ConfigKeys.DEV_SERVICES_CONTAINER_REUSE_ENABLED;
import static org.dependencytrack.common.ConfigKeys.DEV_SERVICES_ENABLED;
import static org.dependencytrack.common.ConfigKeys.DEV_SERVICES_FRONTEND_IMAGE;
import static org.dependencytrack.common.ConfigKeys.DEV_SERVICES_FRONTEND_PORT;
import static org.dependencytrack.common.ConfigKeys.DEV_SERVICES_POSTGRES_IMAGE;

/**
 * @since 5.0.0
 */
public class DevServices implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(DevServices.class);

    private static final String DEV_SERVICES_LABEL = "org.dependencytrack.dev-services";

    private final Config config = ConfigProvider.getConfig();
    private AutoCloseable postgresContainer;
    private AutoCloseable frontendContainer;
    private boolean isContainerReuseActive;

    public void start() {
        if (!config.getValue(DEV_SERVICES_ENABLED, boolean.class)) {
            return;
        }

        final boolean shouldReuseContainers = config.getValue(DEV_SERVICES_CONTAINER_REUSE_ENABLED, boolean.class);

        try {
            // Testcontainers will not be available outside the test scope,
            // except when running via the dev-services Maven profile.
            Class.forName("org.testcontainers.Testcontainers");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("Dev services are not available for production builds");
        }

        // Infer database port and name from the JDBC URL of the primary data source.
        final URI defaultDataSourceUri = URI.create(
                config.getValue("dt.datasource.default.url", String.class).replaceFirst("^jdbc:", "").split("\\?", 2)[0]);
        final String postgresDatabase = defaultDataSourceUri.getPath().replaceFirst("^/", "");
        final int postgresPort = defaultDataSourceUri.getPort();
        final String postgresUsername = config.getValue("dt.datasource.default.username", String.class);
        final String postgresPassword = config.getValue("dt.datasource.default.password", String.class);

        final Integer frontendPort = config.getValue(DEV_SERVICES_FRONTEND_PORT, Integer.class);
        try {
            final Class<?> startablesClass = Class.forName("org.testcontainers.lifecycle.Startables");
            final Method deepStartMethod = startablesClass.getDeclaredMethod("deepStart", Collection.class);

            final Class<?> imagePullPolicyClass = Class.forName("org.testcontainers.images.ImagePullPolicy");
            final Class<?> pullPolicyClass = Class.forName("org.testcontainers.images.PullPolicy");
            final Object alwaysPullPolicy = pullPolicyClass.getDeclaredMethod("alwaysPull").invoke(null);

            final Class<?> genericContainerClass = Class.forName("org.testcontainers.containers.GenericContainer");

            final Method addFixedExposedPortMethod = genericContainerClass.getDeclaredMethod("addFixedExposedPort", int.class, int.class);
            addFixedExposedPortMethod.setAccessible(true);
            final Method withReuseMethod = genericContainerClass.getMethod("withReuse", boolean.class);
            final Method withLabelMethod = genericContainerClass.getMethod("withLabel", String.class, String.class);

            // Reuse only takes effect when it has been opted into globally.
            final Class<?> testcontainersConfigClass = Class.forName("org.testcontainers.utility.TestcontainersConfiguration");
            final Object testcontainersConfig = testcontainersConfigClass.getMethod("getInstance").invoke(null);
            final var envSupportsReuse = (boolean) testcontainersConfigClass.getMethod("environmentSupportsReuse").invoke(testcontainersConfig);
            isContainerReuseActive = shouldReuseContainers && envSupportsReuse;

            final Class<?> postgresContainerClass = Class.forName("org.testcontainers.postgresql.PostgreSQLContainer");
            final Constructor<?> postgresContainerConstructor = postgresContainerClass.getDeclaredConstructor(String.class);
            postgresContainer = (AutoCloseable) postgresContainerConstructor.newInstance(config.getValue(DEV_SERVICES_POSTGRES_IMAGE, String.class));
            postgresContainerClass.getMethod("withUsername", String.class).invoke(postgresContainer, postgresUsername);
            postgresContainerClass.getMethod("withPassword", String.class).invoke(postgresContainer, postgresPassword);
            postgresContainerClass.getMethod("withDatabaseName", String.class).invoke(postgresContainer, postgresDatabase);
            withReuseMethod.invoke(postgresContainer, shouldReuseContainers);
            withLabelMethod.invoke(postgresContainer, DEV_SERVICES_LABEL, "true");
            addFixedExposedPortMethod.invoke(postgresContainer, /* hostPort */ postgresPort, /* containerPort */  5432);

            final String frontendImage = config.getValue(DEV_SERVICES_FRONTEND_IMAGE, String.class);
            final Constructor<?> genericContainerConstructor = genericContainerClass.getDeclaredConstructor(String.class);
            frontendContainer = (AutoCloseable) genericContainerConstructor.newInstance(frontendImage);
            genericContainerClass.getMethod("withEnv", String.class, String.class).invoke(frontendContainer, "API_BASE_URL", "http://localhost:8080");
            genericContainerClass.getMethod("withExposedPorts", Integer[].class).invoke(frontendContainer, (Object) new Integer[]{8080});
            withReuseMethod.invoke(frontendContainer, shouldReuseContainers);
            withLabelMethod.invoke(frontendContainer, DEV_SERVICES_LABEL, "true");
            addFixedExposedPortMethod.invoke(frontendContainer, /* hostPort */ frontendPort, /* containerPort */ 8080);
            if (frontendImage.matches(".*:\\d*-?snapshot")) {
                genericContainerClass.getMethod("withImagePullPolicy", imagePullPolicyClass).invoke(frontendContainer, alwaysPullPolicy);
            }

            LOGGER.info("Starting PostgreSQL and frontend containers");
            final var deepStartFuture = (CompletableFuture<?>) deepStartMethod.invoke(null, List.of(postgresContainer, frontendContainer));
            deepStartFuture.join();
        } catch (Exception e) {
            throw new RuntimeException("Failed to launch containers", e);
        }

        LOGGER.info("PostgreSQL is listening at localhost:{}", postgresPort);
        LOGGER.info("Frontend is listening at http://localhost:{}", frontendPort);
    }

    @Override
    public void close() {
        if (isContainerReuseActive) {
            LOGGER.info("Testcontainers reuse is active; leaving containers running");
            return;
        }

        if (postgresContainer != null) {
            LOGGER.info("Stopping postgres container");
            try {
                postgresContainer.close();
            } catch (Exception e) {
                LOGGER.error("Failed to stop PostgreSQL container", e);
            }
        }
        if (frontendContainer != null) {
            LOGGER.info("Stopping frontend container");
            try {
                frontendContainer.close();
            } catch (Exception e) {
                LOGGER.error("Failed to stop frontend container", e);
            }
        }
    }

}
