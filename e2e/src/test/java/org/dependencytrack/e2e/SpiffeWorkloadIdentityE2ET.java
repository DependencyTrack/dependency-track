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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.e2e.api.v2.ApiException;
import org.dependencytrack.e2e.api.v2.OAuthApi;
import org.dependencytrack.e2e.api.v2.ServiceAccountsApi;
import org.dependencytrack.e2e.api.v2.WorkloadIdentityProvidersApi;
import org.dependencytrack.e2e.api.v2.model.CreateServiceAccountRequest;
import org.dependencytrack.e2e.api.v2.model.CreateWorkloadIdentityBindingRequest;
import org.dependencytrack.e2e.api.v2.model.CreateWorkloadIdentityProviderRequest;
import org.dependencytrack.e2e.api.v2.model.WorkloadIdentityProviderType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class SpiffeWorkloadIdentityE2ET extends AbstractE2ET {

    private static final DockerImageName SPIRE_SERVER_IMAGE =
            DockerImageName.parse("ghcr.io/spiffe/spire-server").withTag("1.15.3");
    private static final String AUDIENCE = "dependency-track-e2e";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private GenericContainer<?> spireServerContainer;

    @Override
    @BeforeEach
    @SuppressWarnings("resource")
    void beforeEach() throws Exception {
        spireServerContainer = new GenericContainer<>(SPIRE_SERVER_IMAGE)
                .withCopyToContainer(Transferable.of(/* language=HCL */ """
                    server {
                      bind_address = "0.0.0.0"
                      bind_port = "8081"
                      trust_domain = "example.org"
                      data_dir = "/tmp/spire/data"
                      log_level = "INFO"
                    }

                    plugins {
                      DataStore "sql" {
                        plugin_data {
                          database_type = "sqlite3"
                          connection_string = "/tmp/spire/data/datastore.sqlite3"
                        }
                      }

                      KeyManager "memory" {
                        plugin_data {}
                      }

                      NodeAttestor "join_token" {
                        plugin_data {}
                      }
                    }
                    """), "/opt/spire/conf/server/server.conf")
                .withCommand("-config", "/opt/spire/conf/server/server.conf")
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("org.dependencytrack.e2e.spire"))
                        .withSeparateOutputStreams())
                .waitingFor(Wait.forLogMessage(".*Starting Server APIs.*api\\.sock.*", 1));
        spireServerContainer.start();

        super.beforeEach();
    }

    @Override
    @AfterEach
    void afterEach() {
        Optional.ofNullable(spireServerContainer).ifPresent(GenericContainer::stop);
        super.afterEach();
    }

    @Test
    void shouldExchangeJwtSvidForSessionOfTheBoundServiceAccount() throws Exception {
        new WorkloadIdentityProvidersApi(apiV2Client)
                .createWorkloadIdentityProvider(new CreateWorkloadIdentityProviderRequest()
                        .name("spire")
                        .type(WorkloadIdentityProviderType.SPIFFE)
                        .issuer("example.org")
                        .audience(AUDIENCE)
                        .jwks(objectMapper.readValue(
                                invokeSpire("bundle", "show", "-format", "spiffe"), new TypeReference<>() {})));
        final var serviceAccountsApi = new ServiceAccountsApi(apiV2Client);
        serviceAccountsApi.createServiceAccount(new CreateServiceAccountRequest().name("ci"));
        serviceAccountsApi.createServiceAccountWorkloadIdentityBinding(
                "ci",
                new CreateWorkloadIdentityBindingRequest()
                        .providerName("spire")
                        .subject("spiffe://example.org/ci/*")
                        .condition("claims.sub.endsWith('/main') && claims.exp > claims.iat"));

        assertThat(getSessionUsername(exchangeToken("spiffe://example.org/ci/main")))
                .isEqualTo("svc:ci");
        assertThatExceptionOfType(ApiException.class)
                .isThrownBy(() -> exchangeToken("spiffe://example.org/ci/feature"))
                .satisfies(e -> assertThat(e.getCode()).isEqualTo(400));
    }

    private String exchangeToken(String spiffeId) throws Exception {
        final String jwtSvid = invokeSpire("jwt", "mint", "-spiffeID", spiffeId, "-audience", AUDIENCE);

        return new OAuthApi(apiV2Client)
                .createOAuthToken(
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                        jwtSvid,
                        "urn:ietf:params:oauth:token-type:jwt",
                        /* requestedTokenType */ null,
                        "spire",
                        "ci")
                .getAccessToken();
    }

    private String getSessionUsername(String sessionToken) throws Exception {
        final HttpResponse<String> response;
        try (final var httpClient = HttpClient.newHttpClient()) {
            response = httpClient.send(
                    HttpRequest.newBuilder(URI.create("http://localhost:%d/api/v1/user/self"
                                    .formatted(apiServerContainer.getFirstMappedPort())))
                            .header("Authorization", "Bearer " + sessionToken)
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
        }
        assertThat(response.statusCode()).isEqualTo(200);
        return objectMapper.readTree(response.body()).get("username").asText();
    }

    private String invokeSpire(String... args) throws Exception {
        final var command = new String[args.length + 1];
        command[0] = "/opt/spire/bin/spire-server";
        System.arraycopy(args, 0, command, 1, args.length);

        final ExecResult result = spireServerContainer.execInContainer(command);
        assertThat(result.getExitCode()).as(result.getStderr()).isZero();
        return result.getStdout().trim();
    }
}
