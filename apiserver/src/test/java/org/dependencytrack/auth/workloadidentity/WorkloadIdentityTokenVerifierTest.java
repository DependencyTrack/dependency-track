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
package org.dependencytrack.auth.workloadidentity;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class WorkloadIdentityTokenVerifierTest {

    private static final String ISSUER = "https://token.actions.githubusercontent.com";
    private static final String AUDIENCE = "https://dependency-track.example.com";

    @RegisterExtension
    private static final WireMockExtension wireMock =
            WireMockExtension.newInstance().options(options().dynamicPort()).build();

    private static HttpClient httpClient;
    private static RSAKey signingKey;

    @BeforeAll
    static void beforeAll() throws Exception {
        httpClient = HttpClient.newHttpClient();
        signingKey = new RSAKeyGenerator(2048).keyID("key-1").generate();
    }

    @AfterAll
    static void afterAll() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

    @ParameterizedTest
    @CsvSource(
            delimiter = '|',
            nullValues = "null",
            value = {"null | {\"keys\": \"not-a-list\"}", "not a url | null"})
    void verifyShouldFailWhenTheStoredKeySourceIsInvalid(String jwksUrl, String jwks) throws Exception {
        final var provider =
                new WorkloadIdentityProvider(WorkloadIdentityProvider.Type.OIDC, ISSUER, AUDIENCE, jwksUrl, jwks);
        final String subjectToken = signedToken(signingKey, claims().build());

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> verifier().verify(provider, subjectToken));
    }

    @Test
    void verifyShouldAcceptKeysMarkedForJwtSvidUse() throws Exception {
        final RSAKey svidKey = new RSAKeyGenerator(2048)
                .keyID("svid-key")
                .keyUse(new KeyUse("jwt-svid"))
                .generate();
        final String subjectToken = signedToken(
                svidKey,
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .subject("spiffe://example.org/ns/default/sa/build")
                        .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                        .build());
        final var provider = new WorkloadIdentityProvider(
                WorkloadIdentityProvider.Type.SPIFFE,
                "example.org",
                AUDIENCE, /* jwksUrl */
                null,
                new JWKSet(svidKey.toPublicJWK()).toString());

        final JWTClaimsSet claimsSet = verifier().verify(provider, subjectToken);
        assertThat(claimsSet.getSubject()).isEqualTo("spiffe://example.org/ns/default/sa/build");
    }

    @Test
    void verifyShouldMatchTheTrustDomainRegardlessOfItsConfiguredCase() throws Exception {
        final String subjectToken = signedToken(
                signingKey, claims(WorkloadIdentityProvider.Type.SPIFFE).build());
        final var provider = new WorkloadIdentityProvider(
                WorkloadIdentityProvider.Type.SPIFFE,
                "Example.ORG",
                AUDIENCE,
                /* jwksUrl */ null,
                new JWKSet(signingKey.toPublicJWK()).toString());

        final JWTClaimsSet claimsSet = verifier().verify(provider, subjectToken);
        assertThat(claimsSet.getSubject()).isEqualTo("spiffe://example.org/ci");
    }

    @Test
    void verifyShouldRefetchKeysWhenTheKeyIdIsUnknown() throws Exception {
        final RSAKey rotatedKey = new RSAKeyGenerator(2048).keyID("key-rotated").generate();
        wireMock.stubFor(get(urlPathEqualTo("/rotating-keys"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(new JWKSet(signingKey.toPublicJWK()).toString())));

        final var provider = new WorkloadIdentityProvider(
                WorkloadIdentityProvider.Type.OIDC,
                ISSUER,
                AUDIENCE,
                wireMock.baseUrl() + "/rotating-keys", /* jwks */
                null);
        final WorkloadIdentityTokenVerifier verifier = verifier();
        verifier.verify(provider, signedToken(signingKey, claims().build()));

        wireMock.stubFor(get(urlPathEqualTo("/rotating-keys"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(new JWKSet(rotatedKey.toPublicJWK()).toString())));

        final JWTClaimsSet claimsSet = verifier.verify(provider, signedToken(rotatedKey, claims().build()));
        assertThat(claimsSet.getSubject()).isEqualTo("repo:acme/app:ref:refs/heads/main");
        wireMock.verify(2, getRequestedFor(urlPathEqualTo("/rotating-keys")));
    }

    @Test
    void verifyShouldRateLimitFetchesWhileTheIssuerIsUnreachable() throws Exception {
        wireMock.stubFor(
                get(urlPathEqualTo("/down-keys")).willReturn(aResponse().withStatus(503)));
        final var provider = new WorkloadIdentityProvider(
                WorkloadIdentityProvider.Type.OIDC,
                ISSUER,
                AUDIENCE,
                wireMock.baseUrl() + "/down-keys", /* jwks */
                null);
        final WorkloadIdentityTokenVerifier verifier = verifier();
        final String subjectToken = signedToken(signingKey, claims().build());

        for (int i = 0; i < 3; i++) {
            assertThatExceptionOfType(KeySourceException.class)
                    .isThrownBy(() -> verifier.verify(provider, subjectToken));
        }
        wireMock.verify(2, getRequestedFor(urlPathEqualTo("/down-keys")));
    }

    @Test
    void verifyShouldKeepUsingFetchedKeysWhileTheIssuerIsUnreachable() throws Exception {
        wireMock.stubFor(get(urlPathEqualTo("/flaky-keys"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(new JWKSet(signingKey.toPublicJWK()).toString())));
        final var provider = new WorkloadIdentityProvider(
                WorkloadIdentityProvider.Type.OIDC,
                ISSUER,
                AUDIENCE,
                wireMock.baseUrl() + "/flaky-keys", /* jwks */
                null);
        final var verifier = new WorkloadIdentityTokenVerifier(
                new WorkloadIdentityKeySetFetcher(httpClient, /* relaxedUrlChecks */ true, Duration.ofSeconds(10)),
                Duration.ofMillis(200),
                Duration.ofMillis(100));
        final String subjectToken = signedToken(signingKey, claims().build());
        verifier.verify(provider, subjectToken);

        wireMock.stubFor(
                get(urlPathEqualTo("/flaky-keys")).willReturn(aResponse().withStatus(503)));
        Thread.sleep(300);

        final JWTClaimsSet claimsSet = verifier.verify(provider, subjectToken);
        assertThat(claimsSet.getSubject()).isEqualTo("repo:acme/app:ref:refs/heads/main");
        wireMock.verify(2, getRequestedFor(urlPathEqualTo("/flaky-keys")));
    }

    private static WorkloadIdentityTokenVerifier verifier() {
        return new WorkloadIdentityTokenVerifier(
                new WorkloadIdentityKeySetFetcher(httpClient, /* relaxedUrlChecks */ true, Duration.ofSeconds(10)));
    }

    private static JWTClaimsSet.Builder claims(WorkloadIdentityProvider.Type type) {
        return switch (type) {
            case OIDC -> claims();
            case SPIFFE -> claims().subject("spiffe://example.org/ci");
        };
    }

    private static JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .subject("repo:acme/app:ref:refs/heads/main")
                .expirationTime(Date.from(Instant.now().plusSeconds(300)));
    }

    private static String signedToken(RSAKey key, JWTClaimsSet claimsSet) throws JOSEException {
        final var signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claimsSet);
        signedJwt.sign(new RSASSASigner(key));
        return signedJwt.serialize();
    }
}
