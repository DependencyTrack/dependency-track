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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.e2e.api.model.CreateTeamRequest;
import org.dependencytrack.e2e.api.model.Team;
import org.dependencytrack.e2e.api.v2.SamlApi;
import org.dependencytrack.e2e.api.v2.model.SamlGroup;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/// Logs in via SAML 2.0 against a Keycloak realm, playing the part of the browser.
///
/// The realm defines the users `alice` (groups `DT-Admins`, `DT-Auditors`), `bob` (`DT-Auditors`)
/// and `carol` (no groups), with the password equal to the username.
class SamlLoginE2ET extends AbstractE2ET {

    private static final DockerImageName KEYCLOAK_IMAGE =
            DockerImageName.parse("quay.io/keycloak/keycloak").withTag("26.4.0");

    // Only used as identifiers in SAML messages, and as redirect targets. The test sends
    // all requests to the mapped ports of the containers, like a browser would to the public URLs.
    private static final String SP_ENTITY_ID = "dependency-track";
    private static final String ACS_URL = "http://dtrack.test/api/v2/saml/acs";
    private static final String FRONTEND_URL = "http://frontend.test";

    private static final String CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final Pattern FORM_ACTION = Pattern.compile("<form[^>]*action=\"([^\"]+)\"");
    private static final Pattern SAML_RESPONSE = Pattern.compile("name=\"SAMLResponse\"\\s+value=\"([^\"]+)\"");

    private final ObjectMapper objectMapper = new ObjectMapper();
    private GenericContainer<?> keycloakContainer;
    private String idpMetadata;

    @Override
    @BeforeEach
    @SuppressWarnings("resource")
    void beforeEach() throws Exception {
        keycloakContainer = new GenericContainer<>(KEYCLOAK_IMAGE)
                .withCommand("start-dev", "--import-realm")
                .withCopyFileToContainer(
                        MountableFile.forClasspathResource("saml/dtrack-realm.json"),
                        "/opt/keycloak/data/import/dtrack-realm.json")
                .withExposedPorts(8080)
                .waitingFor(Wait.forHttp("/realms/dtrack/protocol/saml/descriptor")
                        .forPort(8080)
                        .forStatusCode(200)
                        .withStartupTimeout(Duration.ofMinutes(3)))
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("org.dependencytrack.e2e.keycloak"))
                        .withSeparateOutputStreams());
        keycloakContainer.start();

        // Keycloak derives its URLs from the request. Fetching the metadata via the mapped port
        // makes the single sign-on URL point to where the test can reach it. The API server
        // reads the metadata from a file, so it never needs to reach Keycloak itself.
        idpMetadata = newBrowser()
                .send(
                        HttpRequest.newBuilder(URI.create(keycloakUrl() + "/realms/dtrack/protocol/saml/descriptor"))
                                .build(),
                        HttpResponse.BodyHandlers.ofString())
                .body();

        super.beforeEach();
    }

    @Override
    protected void customizeApiServerContainer(final GenericContainer<?> container) {
        container
                .withCopyToContainer(Transferable.of(idpMetadata), "/tmp/idp-metadata.xml")
                .withEnv("DT_FRONTEND_URL", FRONTEND_URL)
                .withEnv("DT_SAML_ENABLED", "true")
                .withEnv("DT_SAML_SP_ENTITY_ID", SP_ENTITY_ID)
                .withEnv("DT_SAML_SP_ACS_URL", ACS_URL)
                .withEnv("DT_SAML_IDP_METADATA_FILE", "/tmp/idp-metadata.xml")
                .withEnv("DT_SAML_EMAIL_ATTRIBUTE", "email")
                .withEnv("DT_SAML_GROUPS_ATTRIBUTE", "groups")
                .withEnv("DT_SAML_USER_PROVISIONING", "true")
                .withEnv("DT_SAML_TEAM_SYNCHRONIZATION", "true")
                .withEnv("DT_SAML_GROUP_PROVISIONING", "true");
    }

    @AfterEach
    void afterEachKeycloak() {
        Optional.ofNullable(keycloakContainer).ifPresent(GenericContainer::stop);
    }

    @Test
    void shouldProvisionUserAndGroupsAndSynchronizeTeams() throws Exception {
        // The first login creates the user and its groups. No group is mapped to a team yet.
        final JsonNode firstSelf = getSelf(login("alice", "alice"));
        assertThat(firstSelf.get("username").asText()).isEqualTo("alice");
        assertThat(firstSelf.get("email").asText()).isEqualTo("alice@example.com");
        assertThat(firstSelf.path("teams")).isEmpty();

        final var samlApi = new SamlApi(apiV2Client);
        final Map<String, SamlGroup> groupsByName = samlApi.listSamlGroups(null, null, 100).getItems().stream()
                .collect(Collectors.toMap(SamlGroup::getName, group -> group));
        assertThat(groupsByName).containsOnlyKeys("DT-Admins", "DT-Auditors");

        final Team team = apiV1Client.createTeam(new CreateTeamRequest("saml-admins"));
        samlApi.updateSamlGroupMapping(groupsByName.get("DT-Admins").getUuid(), team.uuid());

        // The next login adds the user to all teams that are mapped to one of its groups.
        final JsonNode secondSelf = getSelf(login("alice", "alice"));
        assertThat(secondSelf.path("teams"))
                .extracting(teamNode -> teamNode.get("name").asText())
                .containsExactly("saml-admins");
    }

    @Test
    void shouldRefuseReplayedResponse() throws Exception {
        final HttpClient browser = newBrowser();
        final String samlResponse = authenticateAtIdp(browser, "bob", "bob");

        assertThat(postToAcs(browser, samlResponse)).startsWith(FRONTEND_URL + "/login/saml?code=");
        assertThat(postToAcs(browser, samlResponse)).isEqualTo(FRONTEND_URL + "/login/saml?error=FAILED");
    }

    /// Runs the complete browser flow, and returns the session token.
    private String login(String username, String password) throws Exception {
        final HttpClient browser = newBrowser();

        final String frontendRedirect = postToAcs(browser, authenticateAtIdp(browser, username, password));
        assertThat(frontendRedirect).startsWith(FRONTEND_URL + "/login/saml?");
        final String code = queryParameter(frontendRedirect, "code");
        assertThat(queryParameter(frontendRedirect, "redirect")).isEqualTo("/projects");

        final HttpResponse<String> tokenResponse = browser.send(
                HttpRequest.newBuilder(URI.create(apiServerUrl() + "/api/v2/saml/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(form(Map.of("code", code, "code_verifier", CODE_VERIFIER)))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(tokenResponse.statusCode()).isEqualTo(200);
        return objectMapper.readTree(tokenResponse.body()).get("token").asText();
    }

    /// Starts a login at the API server, logs in at Keycloak, and returns the SAML response that Keycloak posts back.
    private String authenticateAtIdp(HttpClient browser, String username, String password) throws Exception {
        final HttpResponse<Void> startResponse = browser.send(
                HttpRequest.newBuilder(URI.create(apiServerUrl() + "/api/v2/saml/login?code_challenge="
                                + codeChallenge(CODE_VERIFIER) + "&redirect=%2Fprojects"))
                        .build(),
                HttpResponse.BodyHandlers.discarding());
        assertThat(startResponse.statusCode()).isEqualTo(303);
        final String identityProviderUrl =
                startResponse.headers().firstValue("Location").orElseThrow();
        assertThat(identityProviderUrl).startsWith(keycloakUrl());

        final HttpResponse<String> loginPage = browser.send(
                HttpRequest.newBuilder(URI.create(identityProviderUrl)).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(loginPage.statusCode()).isEqualTo(200);

        // Keycloak marks its session cookies as Secure. Browsers send them to http://localhost anyway,
        // but the cookie handling of the JDK HTTP client does not, so pass them on manually.
        final String sessionCookies = loginPage.headers().allValues("Set-Cookie").stream()
                .map(cookie -> cookie.split(";", 2)[0])
                .collect(Collectors.joining("; "));

        final HttpResponse<String> autoPostPage = browser.send(
                HttpRequest.newBuilder(URI.create(htmlUnescape(find(FORM_ACTION, loginPage.body()))))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .header("Cookie", sessionCookies)
                        .POST(form(Map.of("username", username, "password", password)))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(autoPostPage.statusCode()).isEqualTo(200);
        return htmlUnescape(find(SAML_RESPONSE, autoPostPage.body()));
    }

    /// Posts a SAML response to the assertion consumer service, and returns the redirect to the frontend.
    private String postToAcs(HttpClient browser, String samlResponse) throws Exception {
        final HttpResponse<Void> response = browser.send(
                HttpRequest.newBuilder(URI.create(apiServerUrl() + "/api/v2/saml/acs"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(form(Map.of("SAMLResponse", samlResponse)))
                        .build(),
                HttpResponse.BodyHandlers.discarding());
        assertThat(response.statusCode()).isEqualTo(303);
        return response.headers().firstValue("Location").orElseThrow();
    }

    private JsonNode getSelf(String sessionToken) throws Exception {
        final HttpResponse<String> response = newBrowser()
                .send(
                        HttpRequest.newBuilder(URI.create(apiServerUrl() + "/api/v1/user/self"))
                                .header("Authorization", "Bearer " + sessionToken)
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        return objectMapper.readTree(response.body());
    }

    private String apiServerUrl() {
        return "http://localhost:%d".formatted(apiServerContainer.getMappedPort(8080));
    }

    private String keycloakUrl() {
        return "http://localhost:%d".formatted(keycloakContainer.getMappedPort(8080));
    }

    private static HttpClient newBrowser() {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    private static HttpRequest.BodyPublisher form(Map<String, String> parameters) {
        return HttpRequest.BodyPublishers.ofString(parameters.entrySet().stream()
                .map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&")));
    }

    private static String queryParameter(String url, String name) {
        for (final String parameter : URI.create(url).getRawQuery().split("&")) {
            final String[] parts = parameter.split("=", 2);
            if (parts[0].equals(name)) {
                return URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("Missing query parameter %s in %s".formatted(name, url));
    }

    private static String find(Pattern pattern, String html) {
        final Matcher matcher = pattern.matcher(html);
        if (!matcher.find()) {
            throw new AssertionError("Pattern %s not found in page".formatted(pattern));
        }
        return matcher.group(1);
    }

    private static String htmlUnescape(String value) {
        return value.replace("&amp;", "&")
                .replace("&quot;", "\"")
                .replace("&#x3d;", "=")
                .replace("&#61;", "=");
    }

    private static String codeChallenge(String verifier) throws Exception {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    }
}
