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
package org.dependencytrack.e2e;

import feign.Feign;
import feign.jaxrs3.JAXRS3Contract;
import org.dependencytrack.e2e.api.ApiAuthInterceptor;
import org.dependencytrack.e2e.api.ApiClient;
import org.dependencytrack.e2e.api.CompositeDecoder;
import org.dependencytrack.e2e.api.CompositeEncoder;
import org.dependencytrack.e2e.api.model.ApiKey;
import org.dependencytrack.e2e.api.model.CreateTeamRequest;
import org.dependencytrack.e2e.api.model.Team;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.PullPolicy;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.Optional;
import java.util.Set;

abstract class AbstractE2ET {

    protected static DockerImageName POSTGRES_IMAGE = DockerImageName.parse("postgres:14-alpine");
    protected static DockerImageName API_SERVER_IMAGE = DockerImageName.parse("ghcr.io/dependencytrack/apiserver")
            .withTag(Optional.ofNullable(System.getenv("APISERVER_VERSION")).orElse("local"));

    protected final Logger logger = LoggerFactory.getLogger(getClass());
    protected final Network internalNetwork = Network.newNetwork();
    protected PostgreSQLContainer postgresContainer;
    protected GenericContainer<?> apiServerContainer;
    protected ApiClient apiClient;

    @BeforeEach
    void beforeEach() throws Exception {
        postgresContainer = createPostgresContainer();
        postgresContainer.start();

        apiServerContainer = createApiServerContainer();
        apiServerContainer.start();

        apiClient = initializeApiServerClient();
    }

    @SuppressWarnings("resource")
    private PostgreSQLContainer createPostgresContainer() {
        return new PostgreSQLContainer(POSTGRES_IMAGE)
                .withDatabaseName("dtrack")
                .withUsername("dtrack")
                .withPassword("dtrack")
                .withNetworkAliases("postgres")
                .withNetwork(internalNetwork);
    }

    @SuppressWarnings("resource")
    private GenericContainer<?> createApiServerContainer() {
        final var container = new GenericContainer<>(API_SERVER_IMAGE)
                .withImagePullPolicy("local".equals(API_SERVER_IMAGE.getVersionPart()) ? PullPolicy.defaultPolicy() : PullPolicy.alwaysPull())
                .withEnv("JAVA_OPTIONS", "-Xmx512m -XX:+UseSerialGC -XX:TieredStopAtLevel=1")
                .withEnv("DT_DATASOURCE_URL", "jdbc:postgresql://postgres:5432/dtrack")
                .withEnv("DT_DATASOURCE_USERNAME", "dtrack")
                .withEnv("DT_DATASOURCE_PASSWORD", "dtrack")
                .withEnv("ALPINE_BCRYPT_ROUNDS", "4")
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("org.dependencytrack.e2e.apiserver")))
                .waitingFor(Wait.forLogMessage(".*Dependency-Track is ready.*", 1))
                .withNetworkAliases("apiserver")
                .withNetwork(internalNetwork)
                .withExposedPorts(8080);
        customizeApiServerContainer(container);
        return container;
    }

    protected void customizeApiServerContainer(final GenericContainer<?> container) {
    }

    private ApiClient initializeApiServerClient() {
        final ApiClient client = Feign.builder()
                .contract(new JAXRS3Contract())
                .decoder(new CompositeDecoder())
                .encoder(new CompositeEncoder())
                .requestInterceptor(new ApiAuthInterceptor())
                .target(ApiClient.class, "http://localhost:%d".formatted(apiServerContainer.getFirstMappedPort()));

        logger.info("Changing API server admin password");
        client.forcePasswordChange("admin", "admin", "admin123", "admin123");

        logger.info("Authenticating as admin");
        final String bearerToken = client.login("admin", "admin123");
        ApiAuthInterceptor.setBearerToken(bearerToken);

        logger.info("Creating e2e team");
        final Team team = client.createTeam(new CreateTeamRequest("e2e"));

        logger.info("Creating API key for e2e team");
        final ApiKey apiKey = client.createApiKey(team.uuid());

        logger.info("Assigning permissions to e2e team");
        for (final String permission : Set.of(
                "BOM_UPLOAD",
                "POLICY_MANAGEMENT",
                "PORTFOLIO_MANAGEMENT",
                "PROJECT_CREATION_UPLOAD",
                "SECRET_MANAGEMENT_CREATE",
                "SYSTEM_CONFIGURATION",
                "VIEW_PORTFOLIO",
                "VIEW_VULNERABILITY",
                "VULNERABILITY_ANALYSIS",
                "VULNERABILITY_MANAGEMENT"
        )) {
            client.addPermissionToTeam(team.uuid(), permission);
        }

        logger.info("Authenticating as e2e team");
        ApiAuthInterceptor.setApiKey(apiKey.key());

        return client;
    }

    @AfterEach
    void afterEach() {
        ApiAuthInterceptor.reset();

        Optional.ofNullable(apiServerContainer).ifPresent(GenericContainer::stop);
        Optional.ofNullable(postgresContainer).ifPresent(GenericContainer::stop);

        Optional.ofNullable(internalNetwork).ifPresent(Network::close);
    }

}
