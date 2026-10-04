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
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class OidcWorkloadIdentityE2ET extends AbstractE2ET {

    private static final DockerImageName HYDRA_IMAGE =
            DockerImageName.parse("oryd/hydra").withTag("v26.2.0");
    private static final String ISSUER = "https://hydra:4444";
    private static final String AUDIENCE = "dependency-track-e2e";
    private static final char[] STORE_PASSWORD = "changeit".toCharArray();

    private final ObjectMapper objectMapper = new ObjectMapper();
    private GenericContainer<?> hydraContainer;
    private KeyStore trustStore;
    private SSLContext sslContext;

    @TempDir
    Path tempDir;

    @Override
    @BeforeEach
    @SuppressWarnings("resource")
    void beforeEach() throws Exception {
        final Path keyStorePath = tempDir.resolve("hydra.p12");
        final Process keytool = new ProcessBuilder(
                        Path.of(System.getProperty("java.home"), "bin", "keytool")
                                .toString(),
                        "-genkeypair",
                        "-alias",
                        "hydra",
                        "-keyalg",
                        "EC",
                        "-groupname",
                        "secp256r1",
                        "-dname",
                        "CN=hydra",
                        "-ext",
                        "SAN=dns:hydra,dns:localhost",
                        "-validity",
                        "1",
                        "-storetype",
                        "PKCS12",
                        "-keystore",
                        keyStorePath.toString(),
                        "-storepass",
                        new String(STORE_PASSWORD))
                .inheritIO()
                .start();
        assertThat(keytool.waitFor()).isZero();

        final KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (final var inputStream = new FileInputStream(keyStorePath.toFile())) {
            keyStore.load(inputStream, STORE_PASSWORD);
        }
        final Certificate certificate = keyStore.getCertificate("hydra");

        final String tlsCertificatePem = convertToPem("CERTIFICATE", certificate.getEncoded());
        final String tlsPrivateKeyPem = convertToPem(
                "PRIVATE KEY", keyStore.getKey("hydra", STORE_PASSWORD).getEncoded());

        trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("hydra", certificate);

        final var trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        hydraContainer = new GenericContainer<>(HYDRA_IMAGE)
                .withCopyToContainer(Transferable.of(tlsCertificatePem), "/etc/hydra/tls.crt")
                .withCopyToContainer(Transferable.of(tlsPrivateKeyPem), "/etc/hydra/tls.key")
                .withCopyToContainer(
                        Transferable.of(/* language=YAML */ """
                            dsn: memory
                            urls:
                              self:
                                issuer: %s
                                public: %s
                            secrets:
                              system:
                                - e2e-system-secret-do-not-use
                            serve:
                              tls:
                                enabled: true
                                cert:
                                  path: /etc/hydra/tls.crt
                                key:
                                  path: /etc/hydra/tls.key
                            """.formatted(ISSUER, ISSUER)), "/etc/hydra/hydra.yaml")
                .withCommand("serve", "all", "--config", "/etc/hydra/hydra.yaml", "--sqa-opt-out")
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("org.dependencytrack.e2e.hydra"))
                        .withSeparateOutputStreams())
                .waitingFor(Wait.forHttps("/health/ready").forPort(4445).allowInsecure())
                .withNetworkAliases("hydra")
                .withNetwork(internalNetwork)
                .withExposedPorts(4444, 4445);
        hydraContainer.start();

        super.beforeEach();
    }

    @Override
    protected void customizeApiServerContainer(GenericContainer<?> container) {
        final var trustStoreBytes = new ByteArrayOutputStream();
        try {
            trustStore.store(trustStoreBytes, STORE_PASSWORD);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize trust store", e);
        }

        container
                .withCopyToContainer(Transferable.of(trustStoreBytes.toByteArray()), "/tmp/truststore.p12")
                .withEnv(
                        "EXTRA_JAVA_OPTIONS",
                        "-Djavax.net.ssl.trustStore=/tmp/truststore.p12 -Djavax.net.ssl.trustStorePassword=%s"
                                .formatted(new String(STORE_PASSWORD)));
    }

    @Override
    @AfterEach
    void afterEach() {
        Optional.ofNullable(hydraContainer).ifPresent(GenericContainer::stop);
        super.afterEach();
    }

    @Test
    void shouldExchangeHydraAccessTokenForSessionOfTheBoundServiceAccount() throws Exception {
        createHydraClient("ci:main");
        createHydraClient("ci:feature");

        new WorkloadIdentityProvidersApi(apiV2Client)
                .createWorkloadIdentityProvider(new CreateWorkloadIdentityProviderRequest()
                        .name("hydra")
                        .type(WorkloadIdentityProviderType.OIDC)
                        .issuer(ISSUER)
                        .audience(AUDIENCE));
        final var serviceAccountsApi = new ServiceAccountsApi(apiV2Client);
        serviceAccountsApi.createServiceAccount(new CreateServiceAccountRequest().name("ci"));
        serviceAccountsApi.createServiceAccountWorkloadIdentityBinding(
                "ci",
                new CreateWorkloadIdentityBindingRequest().providerName("hydra").subject("ci:main"));

        assertThat(getSessionUsername(exchangeToken("ci:main"))).isEqualTo("svc:ci");
        assertThatExceptionOfType(ApiException.class)
                .isThrownBy(() -> exchangeToken("ci:feature"))
                .satisfies(e -> assertThat(e.getCode()).isEqualTo(400));
    }

    private void createHydraClient(String clientId) throws Exception {
        final HttpResponse<String> response = sendHydraRequest(HttpRequest.newBuilder(
                        URI.create("https://localhost:%d/admin/clients".formatted(hydraContainer.getMappedPort(4445))))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(Map.<String, Object>ofEntries(
                        Map.entry("client_id", clientId),
                        Map.entry("client_secret", "secret"),
                        Map.entry("grant_types", new String[] {"client_credentials"}),
                        Map.entry("token_endpoint_auth_method", "client_secret_post"),
                        Map.entry("access_token_strategy", "jwt"),
                        Map.entry("audience", new String[] {AUDIENCE}))))));
        assertThat(response.statusCode()).as(response.body()).isEqualTo(201);
    }

    private String exchangeToken(String clientId) throws Exception {
        final HttpResponse<String> response = sendHydraRequest(HttpRequest.newBuilder(
                        URI.create("https://localhost:%d/oauth2/token".formatted(hydraContainer.getMappedPort(4444))))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(Map.ofEntries(
                                Map.entry("grant_type", "client_credentials"),
                                Map.entry("client_id", clientId),
                                Map.entry("client_secret", "secret"),
                                Map.entry("audience", AUDIENCE))
                        .entrySet()
                        .stream()
                        .map(entry -> "%s=%s"
                                .formatted(entry.getKey(), URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8)))
                        .collect(Collectors.joining("&")))));
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        final String accessToken =
                objectMapper.readTree(response.body()).get("access_token").asText();

        return new OAuthApi(apiV2Client)
                .createOAuthToken(
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                        accessToken,
                        "urn:ietf:params:oauth:token-type:jwt",
                        /* requestedTokenType */ null,
                        "hydra",
                        "ci")
                .getAccessToken();
    }

    private HttpResponse<String> sendHydraRequest(HttpRequest.Builder requestBuilder) throws Exception {
        try (final var httpClient =
                HttpClient.newBuilder().sslContext(sslContext).build()) {
            return httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        }
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

    private static String convertToPem(String type, byte[] der) {
        return "-----BEGIN %s-----\n%s\n-----END %s-----\n"
                .formatted(type, Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der), type);
    }
}
