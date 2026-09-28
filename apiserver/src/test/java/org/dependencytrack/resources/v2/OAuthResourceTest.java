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

import alpine.model.ServiceAccount;
import com.fasterxml.uuid.Generators;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityBindingDao;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityProvider;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityProviderDao;
import org.dependencytrack.persistence.jdbi.ServiceAccountDao;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

import java.time.Instant;
import java.util.Date;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class OAuthResourceTest extends ResourceTest {

    private static final String ISSUER = "https://token.actions.githubusercontent.com";
    private static final String AUDIENCE = "https://dependency-track.example.com";
    private static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    private static final String ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
    private static final String SUBJECT = "repo:acme/app:ref:refs/heads/main";

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig());

    private RSAKey signingKey;

    @BeforeEach
    public void before() throws Exception {
        super.before();
        signingKey = new RSAKeyGenerator(2048).keyID("key-1").generate();
    }

    @Test
    void createOAuthTokenShouldReturnSessionThatAuthenticatesForMatchingBinding() throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);
        createServiceAccount("ci-pipeline");
        createBinding("github-actions", "ci-pipeline", "repo:acme/app:*", "claims.ref == 'refs/heads/main'");

        final String subjectToken =
                sign(signingKey, claims().claim("ref", "refs/heads/main").build());
        final Response exchangeResponse =
                jersey.target("/oauth/token").request().post(Entity.form(tokenRequest("github-actions", subjectToken)));
        assertThat(exchangeResponse.getStatus()).isEqualTo(200);
        assertThat(exchangeResponse.getHeaderString(HttpHeaders.CACHE_CONTROL)).contains("no-store");
        assertThat(exchangeResponse.getHeaderString("Pragma")).isEqualTo("no-cache");
        final JsonObject exchangeResponseJson = parseJsonObject(exchangeResponse);
        assertThatJson(exchangeResponseJson.toString()).isEqualTo(/* language=JSON */ """
            {
              "access_token": "${json-unit.any-string}",
              "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
              "token_type": "Bearer",
              "expires_in": 3600
            }
            """);

        final Response response = jersey.target("/workload-identity-providers")
                .request()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + exchangeResponseJson.getString("access_token"))
                .get();
        // The service account has no permissions, so reaching the authorization check proves authentication worked.
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void createOAuthTokenShouldRecordWhenTheMatchingBindingWasLastUsed() throws Exception {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);
        createServiceAccount("ci-pipeline");
        createBinding("github-actions", "ci-pipeline", SUBJECT, null);
        createBinding("github-actions", "ci-pipeline", "repo:acme/lib:*", null);

        final String subjectToken = sign(signingKey, claims().build());
        assertThat(jersey.target("/oauth/token")
                        .request()
                        .post(Entity.form(tokenRequest("github-actions", subjectToken)))
                        .getStatus())
                .isEqualTo(200);

        final Response response = jersey.target("/service-accounts/ci-pipeline/workload-identity-bindings")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).inPath("$.items").isEqualTo(/* language=JSON */ """
            [
              {
                "uuid": "${json-unit.any-string}",
                "provider_name": "github-actions",
                "subject": "repo:acme/app:ref:refs/heads/main",
                "created_at": "${json-unit.any-number}",
                "last_used_at": "${json-unit.any-number}"
              },
              {
                "uuid": "${json-unit.any-string}",
                "provider_name": "github-actions",
                "subject": "repo:acme/lib:*",
                "created_at": "${json-unit.any-number}"
              }
            ]
            """);
    }

    private static Stream<Arguments> subjectTokenCases() {
        final var oidc = WorkloadIdentityProvider.Type.OIDC;
        final var spiffe = WorkloadIdentityProvider.Type.SPIFFE;
        final Date anHourAgo = Date.from(Instant.now().minusSeconds(3600));

        return Stream.of(
                arguments("valid OIDC token", oidc, signed(claims -> claims), 200),
                arguments("valid SPIFFE token", spiffe, signed(claims -> claims), 200),
                arguments("typed as at+jwt", oidc, typed("at+jwt"), 200),
                arguments("typed as JOSE", spiffe, typed("JOSE"), 200),
                arguments(
                        "another audience", oidc, signed(claims -> claims.audience("https://other.example.com")), 400),
                arguments("another issuer", oidc, signed(claims -> claims.issuer("https://evil.example.com")), 400),
                arguments("expired", oidc, signed(claims -> claims.expirationTime(anHourAgo)), 400),
                arguments("OIDC without exp", oidc, signed(claims -> claims.expirationTime(null)), 400),
                arguments("SPIFFE without exp", spiffe, signed(claims -> claims.expirationTime(null)), 400),
                arguments(
                        "OIDC with null exp",
                        oidc,
                        signed(claims -> claims.expirationTime(null).serializeNullClaims(true)),
                        400),
                arguments(
                        "SPIFFE with null exp",
                        spiffe,
                        signed(claims -> claims.expirationTime(null).serializeNullClaims(true)),
                        400),
                arguments(
                        "OIDC with null sub",
                        oidc,
                        signed(claims -> claims.subject(null).serializeNullClaims(true)),
                        400),
                arguments(
                        "SPIFFE with null sub",
                        spiffe,
                        signed(claims -> claims.subject(null).serializeNullClaims(true)),
                        400),
                arguments(
                        "SPIFFE from another trust domain",
                        spiffe,
                        signed(claims -> claims.subject("spiffe://other.org/ci")),
                        400),
                arguments(
                        "SPIFFE from a trust domain sharing the prefix",
                        spiffe,
                        signed(claims -> claims.subject("spiffe://example.org.evil/ci")),
                        400),
                arguments("SPIFFE without path", spiffe, signed(claims -> claims.subject("spiffe://example.org")), 400),
                arguments("SPIFFE with non-SPIFFE sub", spiffe, signed(claims -> claims.subject("ci")), 400),
                arguments(
                        "signed by an unknown key",
                        oidc,
                        (SubjectTokenFactory) (_, claims) ->
                                sign(new RSAKeyGenerator(2048).keyID("key-2").generate(), claims.build()),
                        400),
                arguments(
                        "signed with HMAC",
                        oidc,
                        (SubjectTokenFactory) (signingKey, claims) -> {
                            final var signedJwt = new SignedJWT(
                                    new JWSHeader.Builder(JWSAlgorithm.HS256)
                                            .keyID(signingKey.getKeyID())
                                            .build(),
                                    claims.build());
                            signedJwt.sign(new MACSigner("0123456789012345678901234567890123456789"));
                            return signedJwt.serialize();
                        },
                        400));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("subjectTokenCases")
    void createOAuthTokenShouldExchangeOnlyValidSubjectTokens(
            String description,
            WorkloadIdentityProvider.Type type,
            SubjectTokenFactory tokenFactory,
            int expectedStatus)
            throws Exception {
        createProvider("provider", type);
        createServiceAccount("ci-pipeline");
        createBinding("provider", "ci-pipeline", "*", null);

        final JWTClaimsSet.Builder claims =
                type == WorkloadIdentityProvider.Type.SPIFFE ? claims().subject("spiffe://example.org/ci") : claims();

        final Response response = jersey.target("/oauth/token")
                .request()
                .post(Entity.form(tokenRequest("provider", tokenFactory.create(signingKey, claims))));
        assertThat(response.getStatus()).isEqualTo(expectedStatus);
    }

    @ParameterizedTest
    @CsvSource({
        "OIDC, " + JWT_TOKEN_TYPE + ", 200", "OIDC, " + ID_TOKEN_TYPE + ", 200",
        "SPIFFE, " + JWT_TOKEN_TYPE + ", 200", "SPIFFE, " + ID_TOKEN_TYPE + ", 400"
    })
    void createOAuthTokenShouldAcceptIdTokensOnlyForOidcProviders(
            WorkloadIdentityProvider.Type type, String subjectTokenType, int expectedStatus) throws Exception {
        createProvider("provider", type);
        createServiceAccount("ci-pipeline");
        final String subject = type == WorkloadIdentityProvider.Type.SPIFFE ? "spiffe://example.org/ci" : SUBJECT;
        createBinding("provider", "ci-pipeline", subject, null);

        final Form request = tokenRequest(
                "provider", sign(signingKey, claims().subject(subject).build()));
        request.asMap().putSingle("subject_token_type", subjectTokenType);

        final Response response = jersey.target("/oauth/token").request().post(Entity.form(request));
        assertThat(response.getStatus()).isEqualTo(expectedStatus);
    }

    @Test
    void createOAuthTokenShouldUseTheProviderSessionLifetimeRegardlessOfTokenExpiry() throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);
        createServiceAccount("ci-pipeline");
        createBinding("github-actions", "ci-pipeline", "repo:acme/app:*", null);

        final String subjectToken = sign(
                signingKey,
                claims().expirationTime(Date.from(Instant.now().plusSeconds(10)))
                        .build());
        final Response response =
                jersey.target("/oauth/token").request().post(Entity.form(tokenRequest("github-actions", subjectToken)));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(parseJsonObject(response).getInt("expires_in")).isEqualTo(3600);
    }

    @Test
    void createOAuthTokenShouldIssueAccessTokenWhenRequested() throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);
        createServiceAccount("ci-pipeline");
        createBinding("github-actions", "ci-pipeline", SUBJECT, null);

        final Form request = tokenRequest("github-actions", sign(signingKey, claims().build()));
        request.param("requested_token_type", "urn:ietf:params:oauth:token-type:access_token");

        final Response response = jersey.target("/oauth/token").request().post(Entity.form(request));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void createOAuthTokenShouldRefuseRequestedTokenTypeOtherThanAccessToken() throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);
        createServiceAccount("ci-pipeline");
        createBinding("github-actions", "ci-pipeline", SUBJECT, null);

        final Form request = tokenRequest("github-actions", sign(signingKey, claims().build()));
        request.param("requested_token_type", ID_TOKEN_TYPE);

        final Response response = jersey.target("/oauth/token").request().post(Entity.form(request));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
            {
              "error": "invalid_request",
              "error_description": "requested_token_type is not supported"
            }
            """);
    }

    @Test
    void createOAuthTokenShouldRefuseWhenBindingConditionDoesNotMatch() throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);
        createServiceAccount("ci-pipeline");
        createBinding("github-actions", "ci-pipeline", "repo:acme/app:*", "claims.ref == 'refs/heads/main'");

        final String subjectToken =
                sign(signingKey, claims().claim("ref", "refs/heads/dev").build());
        final Response response =
                jersey.target("/oauth/token").request().post(Entity.form(tokenRequest("github-actions", subjectToken)));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).inPath("$.error").isEqualTo("invalid_request");
    }

    @Test
    void createOAuthTokenShouldRefuseWhenBindingConditionDoesNotCompile() throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);
        createServiceAccount("ci-pipeline");
        createBinding("github-actions", "ci-pipeline", "repo:acme/app:*", "claims.ref ==");

        final String subjectToken = sign(signingKey, claims().build());
        final Response response =
                jersey.target("/oauth/token").request().post(Entity.form(tokenRequest("github-actions", subjectToken)));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
            {
              "error": "invalid_request",
              "error_description": "The subject token cannot be exchanged"
            }
            """);
    }

    @Test
    void createOAuthTokenShouldRefuseWhenNoBindingMatchesTheSubject() throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);
        createServiceAccount("ci-pipeline");
        createBinding("github-actions", "ci-pipeline", "repo:acme/other:*", null);

        final String subjectToken = sign(signingKey, claims().build());
        final Response response =
                jersey.target("/oauth/token").request().post(Entity.form(tokenRequest("github-actions", subjectToken)));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).inPath("$.error").isEqualTo("invalid_request");
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
        repo:acme/app:* |                | repo:acme/app:ref:refs/heads/main |
        repo:acme/app:* |                | repo:acme/app:*                   |
        repo:acme/app:* | claims.exp > 0 | repo:acme/app:*                   | has(claims.sub)
        """)
    void createOAuthTokenShouldCreateSessionWhenSeveralBindingsOfTheServiceAccountMatch(
            String firstSubject, String firstCondition, String secondSubject, String secondCondition) throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);
        createServiceAccount("ci-pipeline");
        createBinding("github-actions", "ci-pipeline", firstSubject, firstCondition);
        createBinding("github-actions", "ci-pipeline", secondSubject, secondCondition);

        final String subjectToken = sign(signingKey, claims().build());
        final Response response =
                jersey.target("/oauth/token").request().post(Entity.form(tokenRequest("github-actions", subjectToken)));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void createOAuthTokenShouldCreateSessionOfTheRequestedServiceAccountOnly() throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);
        createServiceAccount("ci-pipeline");
        createServiceAccount("other");
        createBinding("github-actions", "ci-pipeline", "repo:acme/app:*", null);
        createBinding("github-actions", "other", SUBJECT, null);

        final String subjectToken = sign(signingKey, claims().build());
        final Response response =
                jersey.target("/oauth/token").request().post(Entity.form(tokenRequest("github-actions", subjectToken)));
        assertThat(response.getStatus()).isEqualTo(200);

        final String sessionUsername = withJdbiHandle(
                handle -> handle.createQuery("""
                    SELECT u."USERNAME"
                      FROM "USER_SESSION" AS s
                     INNER JOIN "USER" AS u
                        ON u."ID" = s."USER_ID"
                    """).mapTo(String.class).one());
        assertThat(sessionUsername).isEqualTo(ServiceAccount.usernameOf("ci-pipeline"));
    }

    @Test
    void createOAuthTokenShouldRefuseWhenOnlyBindingsOfOtherServiceAccountsMatch() throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);
        createServiceAccount("ci-pipeline");
        createServiceAccount("other");
        createBinding("github-actions", "other", "repo:acme/app:*", null);

        final String subjectToken = sign(signingKey, claims().build());
        final Response response =
                jersey.target("/oauth/token").request().post(Entity.form(tokenRequest("github-actions", subjectToken)));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).inPath("$.error").isEqualTo("invalid_request");
    }

    @Test
    void createOAuthTokenShouldRefuseSuspendedServiceAccount() throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);
        createServiceAccount("ci-pipeline");
        createBinding("github-actions", "ci-pipeline", "repo:acme/app:*", null);
        useJdbiTransaction(handle -> handle.attach(ServiceAccountDao.class)
                .update(ServiceAccount.usernameOf("ci-pipeline"), /* email */ null, /* suspended */ true));

        final String subjectToken = sign(signingKey, claims().build());
        final Response response =
                jersey.target("/oauth/token").request().post(Entity.form(tokenRequest("github-actions", subjectToken)));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).inPath("$.error").isEqualTo("invalid_request");
    }

    @Test
    void createOAuthTokenShouldReturnServiceUnavailableWhenKeysOfProviderCannotBeFetched() throws Exception {
        useJdbiTransaction(handle -> handle.attach(WorkloadIdentityProviderDao.class)
                .create(
                        "unreachable",
                        WorkloadIdentityProvider.Type.OIDC,
                        ISSUER,
                        AUDIENCE,
                        "https://keys.invalid/jwks",
                        /* jwks */ null,
                        3600));
        createServiceAccount("ci-pipeline");
        createBinding("unreachable", "ci-pipeline", SUBJECT, null);

        final String subjectToken = sign(signingKey, claims().build());
        final Response response =
                jersey.target("/oauth/token").request().post(Entity.form(tokenRequest("unreachable", subjectToken)));
        assertThat(response.getStatus()).isEqualTo(503);
    }

    @Test
    void createOAuthTokenShouldRefuseUnknownProvider() throws Exception {
        final String subjectToken = sign(signingKey, claims().build());
        final Response response =
                jersey.target("/oauth/token").request().post(Entity.form(tokenRequest("nope", subjectToken)));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString(HttpHeaders.CACHE_CONTROL)).contains("no-store");
        assertThat(response.getHeaderString("Pragma")).isEqualTo("no-cache");
        assertThatJson(getPlainTextBody(response)).inPath("$.error").isEqualTo("invalid_request");
    }

    @Test
    void createOAuthTokenShouldRefuseUnsupportedGrantType() throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);

        final Form request = tokenRequest("github-actions", sign(signingKey, claims().build()));
        request.asMap().putSingle("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");

        final Response response = jersey.target("/oauth/token").request().post(Entity.form(request));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).inPath("$.error").isEqualTo("unsupported_grant_type");
    }

    @ParameterizedTest
    @ValueSource(strings = {"urn:ietf:params:oauth:token-type:access_token", "urn:ietf:params:oauth:token-type:saml2"})
    void createOAuthTokenShouldRefuseUnsupportedSubjectTokenType(String subjectTokenType) throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);

        final Form request = tokenRequest("github-actions", sign(signingKey, claims().build()));
        request.asMap().putSingle("subject_token_type", subjectTokenType);

        final Response response = jersey.target("/oauth/token").request().post(Entity.form(request));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString(HttpHeaders.CACHE_CONTROL)).contains("no-store");
        assertThat(response.getHeaderString("Pragma")).isEqualTo("no-cache");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
            {
              "error": "invalid_request",
              "error_description": "subject_token_type is not supported"
            }
            """);
    }

    @ParameterizedTest
    @ValueSource(strings = {"subject_token", "subject_token_type", "workload_identity_provider", "service_account"})
    void createOAuthTokenShouldRefuseRequestWithoutRequiredParameter(String parameter) throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);

        final Form request = tokenRequest("github-actions", sign(signingKey, claims().build()));
        request.asMap().remove(parameter);

        final Response response = jersey.target("/oauth/token").request().post(Entity.form(request));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString(HttpHeaders.CACHE_CONTROL)).contains("no-store");
        assertThat(response.getHeaderString("Pragma")).isEqualTo("no-cache");
        assertThatJson(getPlainTextBody(response)).inPath("$.error").isEqualTo("invalid_request");
    }

    private static Stream<Arguments> malformedNameParameters() {
        return Stream.of(
                arguments("workload_identity_provider", "github-actions\nforged log line"),
                arguments("workload_identity_provider", "a".repeat(64)),
                arguments("service_account", "ci-pipeline\nforged log line"),
                arguments("service_account", "svc:ci-pipeline"),
                arguments("service_account", "a".repeat(60)));
    }

    @ParameterizedTest
    @MethodSource("malformedNameParameters")
    void createOAuthTokenShouldRefuseMalformedName(String parameter, String value) throws Exception {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);

        final Form request = tokenRequest("github-actions", sign(signingKey, claims().build()));
        request.asMap().putSingle(parameter, value);

        final Response response = jersey.target("/oauth/token").request().post(Entity.form(request));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
            {
              "error": "invalid_request",
              "error_description": "%s is invalid"
            }
            """.formatted(parameter));
    }

    @Test
    void createOAuthTokenShouldRefuseSubjectTokenExceedingTheSizeLimit() {
        createProvider("github-actions", WorkloadIdentityProvider.Type.OIDC);

        final Response response = jersey.target("/oauth/token")
                .request()
                .post(Entity.form(tokenRequest("github-actions", "x".repeat(16 * 1024 + 1))));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).inPath("$.error").isEqualTo("invalid_request");
    }

    private interface SubjectTokenFactory {

        String create(RSAKey signingKey, JWTClaimsSet.Builder claims) throws JOSEException;
    }

    private static SubjectTokenFactory signed(UnaryOperator<JWTClaimsSet.Builder> customizer) {
        return (signingKey, claims) -> sign(signingKey, customizer.apply(claims).build());
    }

    private static SubjectTokenFactory typed(String type) {
        return (signingKey, claims) -> {
            final var signedJwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .type(new JOSEObjectType(type))
                            .keyID(signingKey.getKeyID())
                            .build(),
                    claims.build());
            signedJwt.sign(new RSASSASigner(signingKey));
            return signedJwt.serialize();
        };
    }

    private static Form tokenRequest(String providerName, String subjectToken) {
        return new Form()
                .param("grant_type", TOKEN_EXCHANGE_GRANT)
                .param("subject_token", subjectToken)
                .param("subject_token_type", JWT_TOKEN_TYPE)
                .param("workload_identity_provider", providerName)
                .param("service_account", "ci-pipeline");
    }

    private JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .subject(SUBJECT)
                .expirationTime(Date.from(Instant.now().plusSeconds(7200)));
    }

    private static String sign(RSAKey signingKey, JWTClaimsSet claimsSet) throws JOSEException {
        final var signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(signingKey.getKeyID())
                        .build(),
                claimsSet);
        signedJwt.sign(new RSASSASigner(signingKey));
        return signedJwt.serialize();
    }

    private void createProvider(String name, WorkloadIdentityProvider.Type type) {
        useJdbiTransaction(handle -> handle.attach(WorkloadIdentityProviderDao.class)
                .create(
                        name,
                        type,
                        type == WorkloadIdentityProvider.Type.SPIFFE ? "example.org" : ISSUER,
                        AUDIENCE,
                        /* jwksUrl */ null,
                        new JWKSet(signingKey.toPublicJWK()).toString(),
                        3600));
    }

    private static void createServiceAccount(String name) {
        useJdbiTransaction(
                handle -> handle.attach(ServiceAccountDao.class).create(ServiceAccount.usernameOf(name), null));
    }

    private static void createBinding(
            String providerName, String serviceAccountName, String subject, String condition) {
        useJdbiTransaction(handle -> handle.attach(WorkloadIdentityBindingDao.class)
                .create(
                        Generators.timeBasedEpochRandomGenerator().generate(),
                        providerName,
                        ServiceAccount.usernameOf(serviceAccountName),
                        subject,
                        condition));
    }
}
