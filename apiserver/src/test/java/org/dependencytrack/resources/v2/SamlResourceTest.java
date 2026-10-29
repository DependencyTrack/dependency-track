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
package org.dependencytrack.resources.v2;

import alpine.model.SamlUser;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.auth.saml.SamlConfig;
import org.dependencytrack.auth.saml.SamlLoginService;
import org.dependencytrack.auth.saml.SamlLoginServiceHolder;
import org.dependencytrack.auth.saml.TestIdentityProvider;
import org.dependencytrack.auth.saml.TestIdentityProvider.ResponseSpec;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.Response;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.auth.saml.TestIdentityProvider.ACS_URL;
import static org.dependencytrack.auth.saml.TestIdentityProvider.SP_ENTITY_ID;
import static org.dependencytrack.auth.saml.TestIdentityProvider.codeChallenge;
import static org.dependencytrack.auth.saml.TestIdentityProvider.decodeAuthnRequest;
import static org.dependencytrack.auth.saml.TestIdentityProvider.signedAssertionResponse;

class SamlResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig());

    private static final String CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @TempDir
    private Path tempDir;

    @AfterEach
    void resetSaml() {
        SamlLoginServiceHolder.reset();
    }

    private void enableSaml() throws Exception {
        final Path metadataFile = tempDir.resolve("idp-metadata.xml");
        Files.writeString(metadataFile, TestIdentityProvider.metadataXml());
        SamlLoginServiceHolder.set(new SamlLoginService(new SamlConfig(
                SP_ENTITY_ID,
                ACS_URL,
                URI.create("https://dtrack.example.com/"),
                null,
                metadataFile,
                null,
                null,
                null,
                true,
                false,
                false,
                List.of())));
    }

    @Test
    void shouldReportSamlAsUnavailableWhenDisabled() {
        SamlLoginServiceHolder.set(null);

        final Response response = jersey.target("/saml/availability").request().get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(parseJsonObject(response).getBoolean("enabled")).isFalse();
    }

    @Test
    void shouldRespondWithNotFoundWhenDisabled() {
        SamlLoginServiceHolder.set(null);

        assertThat(jersey.target("/saml/metadata").request().get().getStatus()).isEqualTo(404);
        assertThat(jersey.target("/saml/login")
                        .queryParam("code_challenge", codeChallenge(CODE_VERIFIER))
                        .request()
                        .property(ClientProperties.FOLLOW_REDIRECTS, false)
                        .get()
                        .getStatus())
                .isEqualTo(404);
    }

    @Test
    void shouldServeServiceProviderMetadata() throws Exception {
        enableSaml();

        // The validation filter can only validate JSON responses.
        final Response response = jersey.target("/saml/metadata")
                .request()
                .property(OpenApiValidationClientResponseFilter.DISABLE_OPENAPI_VALIDATION, true)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getMediaType().toString()).isEqualTo("application/samlmetadata+xml");
        assertThat(response.readEntity(String.class))
                .contains("entityID=\"" + SP_ENTITY_ID + "\"")
                .contains("Location=\"" + ACS_URL + "\"");
    }

    @Test
    void shouldCompleteLoginFlow() throws Exception {
        enableSaml();

        final Response availability =
                jersey.target("/saml/availability").request().get();
        assertThat(parseJsonObject(availability).getBoolean("enabled")).isTrue();

        // The browser starts the login, and is sent to the IdP.
        final Response loginResponse = jersey.target("/saml/login")
                .queryParam("code_challenge", codeChallenge(CODE_VERIFIER))
                .queryParam("redirect", "/projects")
                .request()
                .property(ClientProperties.FOLLOW_REDIRECTS, false)
                .get();
        assertThat(loginResponse.getStatus()).isEqualTo(303);
        final String requestId = decodeAuthnRequest(loginResponse.getLocation()).getAttribute("ID");

        // The IdP posts the response, and the browser is sent to the frontend with a code.
        final ResponseSpec spec = new ResponseSpec();
        spec.inResponseTo = requestId;
        final Response acsResponse = postAcs(signedAssertionResponse(spec));
        assertThat(acsResponse.getStatus()).isEqualTo(303);
        final URI frontendUrl = acsResponse.getLocation();
        assertThat(frontendUrl.getScheme() + "://" + frontendUrl.getHost() + frontendUrl.getPath())
                .isEqualTo("https://dtrack.example.com/login/saml");
        final Map<String, String> query = queryParameters(frontendUrl);
        assertThat(query).containsEntry("redirect", "/projects").containsKey("code");

        // The frontend exchanges the code for a session token.
        final Response tokenResponse = jersey.target("/saml/token")
                .request()
                .post(Entity.form(new Form().param("code", query.get("code")).param("code_verifier", CODE_VERIFIER)));
        assertThat(tokenResponse.getStatus()).isEqualTo(200);
        assertThat(tokenResponse.getHeaderString("Cache-Control")).contains("no-store");
        assertThat(parseJsonObject(tokenResponse).getString("token")).isNotBlank();
        assertThat(qm.getUser("jane.doe@example.com")).isInstanceOf(SamlUser.class);

        // The code can only be used once.
        final Response secondTokenResponse = jersey.target("/saml/token")
                .request()
                .post(Entity.form(new Form().param("code", query.get("code")).param("code_verifier", CODE_VERIFIER)));
        assertThat(secondTokenResponse.getStatus()).isEqualTo(400);
    }

    @Test
    void shouldRedirectToFrontendWithErrorForInvalidResponse() throws Exception {
        enableSaml();

        final Response response =
                postAcs(TestIdentityProvider.encode(TestIdentityProvider.responseXml(new ResponseSpec())));

        assertThat(response.getStatus()).isEqualTo(303);
        assertThat(queryParameters(response.getLocation()))
                .containsEntry("error", "FAILED")
                .doesNotContainKey("code");
    }

    @Test
    void shouldRefuseInvalidCodeChallenge() throws Exception {
        enableSaml();

        final Response response = jersey.target("/saml/login")
                .queryParam("code_challenge", "too-short")
                .request()
                .property(ClientProperties.FOLLOW_REDIRECTS, false)
                .get();

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void shouldManageSamlGroupsAndMappings() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT, Permissions.ACCESS_MANAGEMENT_READ);
        final String teamUuid = qm.createTeam("Admins").getUuid().toString();

        final Response created = jersey.target("/saml-groups")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json("""
                        {"name": "CONTOSO\\\\DT-Admins"}
                        """));
        assertThat(created.getStatus()).isEqualTo(201);
        final String groupUuid =
                Path.of(created.getLocation().getPath()).getFileName().toString();

        final Response duplicate = jersey.target("/saml-groups")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json("""
                        {"name": "CONTOSO\\\\DT-Admins"}
                        """));
        assertThat(duplicate.getStatus()).isEqualTo(409);

        assertThat(jersey.target("/saml-groups/%s/teams/%s".formatted(groupUuid, teamUuid))
                        .request()
                        .header(X_API_KEY, apiKey)
                        .put(Entity.text(""))
                        .getStatus())
                .isEqualTo(204);

        final Response list = jersey.target("/saml-groups")
                .queryParam("team_uuid", teamUuid)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(list.getStatus()).isEqualTo(200);
        final JsonObject group = parseJsonObject(list).getJsonArray("items").getJsonObject(0);
        assertThat(group.getString("name")).isEqualTo("CONTOSO\\DT-Admins");
        assertThat(group.getJsonArray("teams").getJsonObject(0).getString("name"))
                .isEqualTo("Admins");

        assertThat(jersey.target("/saml-groups/%s/teams/%s".formatted(groupUuid, teamUuid))
                        .request()
                        .header(X_API_KEY, apiKey)
                        .delete()
                        .getStatus())
                .isEqualTo(204);
        assertThat(jersey.target("/saml-groups/" + groupUuid)
                        .request()
                        .header(X_API_KEY, apiKey)
                        .delete()
                        .getStatus())
                .isEqualTo(204);
        assertThat(jersey.target("/saml-groups/" + groupUuid)
                        .request()
                        .header(X_API_KEY, apiKey)
                        .delete()
                        .getStatus())
                .isEqualTo(404);
    }

    @Test
    void shouldManageSamlUsers() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);
        qm.createManagedUser("existing", "not-a-real-hash");

        assertThat(jersey.target("/saml-users")
                        .request()
                        .header(X_API_KEY, apiKey)
                        .post(Entity.json("""
                                {"username": "jane"}
                                """))
                        .getStatus())
                .isEqualTo(201);
        assertThat(jersey.target("/saml-users")
                        .request()
                        .header(X_API_KEY, apiKey)
                        .post(Entity.json("""
                                {"username": "existing"}
                                """))
                        .getStatus())
                .isEqualTo(409);
        assertThat(jersey.target("/saml-users")
                        .request()
                        .header(X_API_KEY, apiKey)
                        .post(Entity.json("""
                                {"username": "svc:ci"}
                                """))
                        .getStatus())
                .isEqualTo(400);

        final Response list =
                jersey.target("/saml-users").request().header(X_API_KEY, apiKey).get();
        assertThat(list.getStatus()).isEqualTo(200);
        final JsonObject user = parseJsonObject(list).getJsonArray("items").getJsonObject(0);
        assertThat(user.getString("username")).isEqualTo("jane");
        assertThat(user.getJsonArray("teams")).isEmpty();
        assertThat(user.getJsonArray("permissions")).isEmpty();

        assertThat(jersey.target("/saml-users/jane")
                        .request()
                        .header(X_API_KEY, apiKey)
                        .delete()
                        .getStatus())
                .isEqualTo(204);
        assertThat(jersey.target("/saml-users/existing")
                        .request()
                        .header(X_API_KEY, apiKey)
                        .delete()
                        .getStatus())
                .isEqualTo(404);
    }

    private Response postAcs(String samlResponse) {
        return jersey.target("/saml/acs")
                .request()
                .property(ClientProperties.FOLLOW_REDIRECTS, false)
                .post(Entity.form(new Form().param("SAMLResponse", samlResponse)));
    }

    private static Map<String, String> queryParameters(URI uri) {
        return Arrays.stream(uri.getRawQuery().split("&"))
                .map(parameter -> parameter.split("=", 2))
                .collect(Collectors.toMap(
                        parameter -> parameter[0],
                        parameter -> URLDecoder.decode(parameter[1], StandardCharsets.UTF_8)));
    }
}
