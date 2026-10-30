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
package org.dependencytrack.auth.saml;

import alpine.model.SamlUser;
import alpine.model.Team;
import alpine.model.User;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.auth.saml.SamlLoginService.CompletedLogin;
import org.dependencytrack.auth.saml.SamlLoginService.FailureReason;
import org.dependencytrack.auth.saml.SamlLoginService.LoginRefusedException;
import org.dependencytrack.auth.saml.TestIdentityProvider.ResponseSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.auth.saml.TestIdentityProvider.ACS_URL;
import static org.dependencytrack.auth.saml.TestIdentityProvider.SP_ENTITY_ID;
import static org.dependencytrack.auth.saml.TestIdentityProvider.codeChallenge;
import static org.dependencytrack.auth.saml.TestIdentityProvider.decodeAuthnRequest;
import static org.dependencytrack.auth.saml.TestIdentityProvider.signedAssertionResponse;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class SamlLoginServiceTest extends PersistenceCapableTest {

    private static final String GROUPS_ATTRIBUTE = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups";
    private static final String EMAIL_ATTRIBUTE = "email";
    private static final String CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @TempDir
    private Path tempDir;

    private Path metadataFile;

    @BeforeEach
    void writeMetadata() throws Exception {
        metadataFile = tempDir.resolve("idp-metadata.xml");
        Files.writeString(metadataFile, TestIdentityProvider.metadataXml());
    }

    private SamlLoginService createService(
            boolean userProvisioning,
            boolean teamSynchronization,
            boolean groupProvisioning,
            List<String> defaultTeams) {
        final var config = new SamlConfig(
                SP_ENTITY_ID,
                ACS_URL,
                URI.create("https://dtrack.example.com"),
                null,
                metadataFile,
                null,
                EMAIL_ATTRIBUTE,
                GROUPS_ATTRIBUTE,
                userProvisioning,
                teamSynchronization,
                groupProvisioning,
                defaultTeams);
        return new SamlLoginService(
                config,
                new SamlIdpMetadataProvider(null, metadataFile, HttpClient.newHttpClient(), Clock.systemUTC()),
                new SamlResponseValidator(config),
                Clock.systemUTC());
    }

    private SamlLoginService createService() {
        return createService(true, false, false, List.of());
    }

    @Test
    void shouldCompleteLoginAndExchangeCode() throws Exception {
        final SamlLoginService service = createService();

        final URI identityProviderUrl = service.startLogin(codeChallenge(CODE_VERIFIER), "/projects?page=2");
        final Element authnRequest = decodeAuthnRequest(identityProviderUrl);
        assertThat(identityProviderUrl.toString()).startsWith(TestIdentityProvider.SSO_URL + "?SAMLRequest=");
        assertThat(authnRequest.getAttribute("AssertionConsumerServiceURL")).isEqualTo(ACS_URL.toString());
        assertThat(authnRequest.getAttribute("Destination")).isEqualTo(TestIdentityProvider.SSO_URL.toString());
        assertThat(authnRequest.getTextContent()).isEqualTo(SP_ENTITY_ID);

        final ResponseSpec spec = new ResponseSpec().attribute(EMAIL_ATTRIBUTE, "jane@example.com");
        spec.inResponseTo = authnRequest.getAttribute("ID");
        final CompletedLogin login = service.completeLogin(signedAssertionResponse(spec));

        assertThat(login.username()).isEqualTo("jane.doe@example.com");
        assertThat(login.redirectPath()).isEqualTo("/projects?page=2");

        final Long userId = SamlLoginService.exchangeCode(login.code(), CODE_VERIFIER, Instant.now());
        final User user = qm.getUser("jane.doe@example.com");
        assertThat(user).isInstanceOf(SamlUser.class);
        assertThat(userId).isEqualTo(user.getId());
        assertThat(user.getEmail()).isEqualTo("jane@example.com");
    }

    @Test
    void shouldIgnoreUnsafeRedirectPath() throws Exception {
        final SamlLoginService service = createService();

        final String requestId = decodeAuthnRequest(
                        service.startLogin(codeChallenge(CODE_VERIFIER), "//evil.example.com"))
                .getAttribute("ID");

        assertThat(complete(service, requestId).redirectPath()).isNull();
    }

    @Test
    void shouldRefuseCodeWithWrongVerifier() throws Exception {
        final SamlLoginService service = createService();
        final CompletedLogin login = complete(service, start(service));

        assertThat(SamlLoginService.exchangeCode(login.code(), "x".repeat(43), Instant.now()))
                .isNull();
        // A failed attempt consumes the code, so it cannot be guessed against.
        assertThat(SamlLoginService.exchangeCode(login.code(), CODE_VERIFIER, Instant.now()))
                .isNull();
    }

    @Test
    void shouldRefuseCodeReuse() throws Exception {
        final SamlLoginService service = createService();
        final CompletedLogin login = complete(service, start(service));

        assertThat(SamlLoginService.exchangeCode(login.code(), CODE_VERIFIER, Instant.now()))
                .isNotNull();
        assertThat(SamlLoginService.exchangeCode(login.code(), CODE_VERIFIER, Instant.now()))
                .isNull();
    }

    @Test
    void shouldRefuseExpiredCode() throws Exception {
        final SamlLoginService service = createService();
        final CompletedLogin login = complete(service, start(service));

        assertThat(SamlLoginService.exchangeCode(
                        login.code(), CODE_VERIFIER, Instant.now().plus(SamlLoginService.LOGIN_CODE_LIFETIME)))
                .isNull();
    }

    @Test
    void shouldRefuseReplayedResponse() throws Exception {
        final SamlLoginService service = createService();
        final String requestId = start(service);
        final String response = response(requestId, new ResponseSpec());

        service.completeLogin(response);

        assertRefused(service, response, FailureReason.FAILED);
    }

    @Test
    void shouldRefuseUnsolicitedResponse() {
        assertRefused(createService(), response("_unknownRequest", new ResponseSpec()), FailureReason.FAILED);
    }

    @Test
    void shouldRefuseUnknownUserWithoutProvisioning() throws Exception {
        final SamlLoginService service = createService(false, false, false, List.of());

        assertRefused(service, response(start(service), new ResponseSpec()), FailureReason.UNMAPPED_ACCOUNT);
        assertThat(qm.getUser("jane.doe@example.com")).isNull();
    }

    @Test
    void shouldLoginExistingUserWithoutProvisioning() throws Exception {
        withJdbiHandle(handle -> handle.attach(SamlUserDao.class).createUser("jane.doe@example.com", null));
        final SamlLoginService service = createService(false, false, false, List.of());

        assertThat(complete(service, start(service)).username()).isEqualTo("jane.doe@example.com");
    }

    @Test
    void shouldRefuseTakeoverOfUserWithOtherType() throws Exception {
        qm.createManagedUser("jane.doe@example.com", TEST_PASSWORD_HASH);
        final SamlLoginService service = createService();

        assertRefused(service, response(start(service), new ResponseSpec()), FailureReason.FAILED);
    }

    @Test
    void shouldRefuseReservedServiceAccountPrefix() throws Exception {
        final SamlLoginService service = createService();
        final ResponseSpec spec = new ResponseSpec();
        spec.nameId = "svc:ci";

        assertRefused(service, response(start(service), spec), FailureReason.FAILED);
    }

    @Test
    void shouldAddProvisionedUserToDefaultTeams() throws Exception {
        qm.createTeam("Default");
        final SamlLoginService service = createService(true, false, false, List.of("Default", "Missing"));

        complete(service, start(service));

        assertThat(qm.getUser("jane.doe@example.com").getTeams())
                .extracting(Team::getName)
                .containsExactly("Default");
    }

    @Test
    void shouldCreateGroupsVerbatim() throws Exception {
        final SamlLoginService service = createService(true, false, true, List.of());
        final ResponseSpec spec = new ResponseSpec().attribute(GROUPS_ATTRIBUTE, "CONTOSO\\DT-Admins", "dt-admins");

        complete(service, start(service), spec);
        complete(service, start(service), spec);

        assertThat(groupNames()).containsExactly("CONTOSO\\DT-Admins", "dt-admins");
    }

    @Test
    void shouldSynchronizeTeams() throws Exception {
        final Team admins = qm.createTeam("Admins");
        final Team auditors = qm.createTeam("Auditors");
        final Team unrelated = qm.createTeam("Unrelated");
        withJdbiHandle(handle -> {
            final var dao = handle.attach(SamlGroupDao.class);
            dao.createGroups(List.of("DT-Admins", "DT-Auditors"));
            final var groups = dao.listGroups(10, null, null).items();
            dao.createMapping(groups.get(0).uuid(), admins.getUuid().toString());
            dao.createMapping(groups.get(1).uuid(), auditors.getUuid().toString());
            return null;
        });
        final SamlLoginService service = createService(true, true, false, List.of("Unrelated"));

        complete(service, start(service), new ResponseSpec().attribute(GROUPS_ATTRIBUTE, "DT-Admins"));
        qm.addUserToTeam(qm.getUser("jane.doe@example.com"), unrelated);

        complete(service, start(service), new ResponseSpec().attribute(GROUPS_ATTRIBUTE, "DT-Auditors", "Unknown"));

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getUser("jane.doe@example.com").getTeams())
                .extracting(Team::getName)
                .containsExactly("Auditors");
    }

    private String start(SamlLoginService service) throws Exception {
        return decodeAuthnRequest(service.startLogin(codeChallenge(CODE_VERIFIER), null))
                .getAttribute("ID");
    }

    private CompletedLogin complete(SamlLoginService service, String requestId) throws Exception {
        return complete(service, requestId, new ResponseSpec());
    }

    private CompletedLogin complete(SamlLoginService service, String requestId, ResponseSpec spec) throws Exception {
        return service.completeLogin(response(requestId, spec));
    }

    private static String response(String requestId, ResponseSpec spec) {
        spec.inResponseTo = requestId;
        return signedAssertionResponse(spec);
    }

    private static void assertRefused(SamlLoginService service, String response, FailureReason reason) {
        assertThatExceptionOfType(LoginRefusedException.class)
                .isThrownBy(() -> service.completeLogin(response))
                .satisfies(e -> assertThat(e.reason()).isEqualTo(reason));
    }

    private static List<String> groupNames() {
        return withJdbiHandle(
                handle -> handle.createQuery("""
                        SELECT "NAME" FROM "SAML_GROUP" ORDER BY "NAME"
                        """).mapTo(String.class).list());
    }
}
