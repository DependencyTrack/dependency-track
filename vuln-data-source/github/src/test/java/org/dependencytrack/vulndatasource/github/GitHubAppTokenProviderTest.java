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
package org.dependencytrack.vulndatasource.github;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GitHubAppTokenProviderTest {

    private static String testKeyPem() throws Exception {
        try (var in = GitHubAppTokenProviderTest.class.getResourceAsStream("test-app-key.pem")) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static PublicKey publicKeyOf(final PrivateKey privateKey) throws Exception {
        final var crt = (RSAPrivateCrtKey) privateKey;
        return java.security.KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
    }

    @Test
    void parsePrivateKeyShouldParsePkcs8PemIntoUsableSigningKey() throws Exception {
        final PrivateKey privateKey = GitHubAppTokenProvider.parsePrivateKey(testKeyPem());

        final byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
        final var signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(data);
        final byte[] signature = signer.sign();

        final var verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKeyOf(privateKey));
        verifier.update(data);
        assertThat(verifier.verify(signature)).isTrue();
    }

    @Test
    void parsePrivateKeyShouldRejectPkcs1WithConversionHint() {
        final String pkcs1 = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";

        assertThatThrownBy(() -> GitHubAppTokenProvider.parsePrivateKey(pkcs1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("openssl pkcs8 -topk8 -nocrypt");
    }

    @Test
    void buildAppJwtShouldSetClaimsAndSignWithAppKey() throws Exception {
        final PrivateKey privateKey = GitHubAppTokenProvider.parsePrivateKey(testKeyPem());
        final var clock = Clock.fixed(Instant.ofEpochSecond(1_000_000), ZoneOffset.UTC);

        final String jwt = GitHubAppTokenProvider.buildAppJwt("123456", privateKey, clock);

        final String[] parts = jwt.split("\\.");
        assertThat(parts).hasSize(3);

        final var urlDecoder = Base64.getUrlDecoder();
        final String header = new String(urlDecoder.decode(parts[0]), StandardCharsets.UTF_8);
        final String claims = new String(urlDecoder.decode(parts[1]), StandardCharsets.UTF_8);

        assertThatJson(header).isEqualTo("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        assertThatJson(claims).and(
                a -> a.node("iss").isString().isEqualTo("123456"),
                a -> a.node("iat").isEqualTo(1_000_000 - 60),
                a -> a.node("exp").isEqualTo(1_000_000 + 300));

        // Signature covers "<header>.<claims>" and verifies with the App public key.
        final var verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKeyOf(privateKey));
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
        assertThat(verifier.verify(urlDecoder.decode(parts[2]))).isTrue();
    }

    @Test
    void tokenExchangeBaseUrlShouldUseApiHostForGithubDotCom() {
        assertThat(GitHubAppTokenProvider.tokenExchangeBaseUrl(URI.create("https://api.github.com/graphql")))
                .isEqualTo("https://api.github.com");
    }

    @Test
    void tokenExchangeBaseUrlShouldUseApiV3PathForEnterpriseServer() {
        assertThat(GitHubAppTokenProvider.tokenExchangeBaseUrl(URI.create("https://ghe.example.com/api/graphql")))
                .isEqualTo("https://ghe.example.com/api/v3");
    }

    @Nested
    @WireMockTest
    class TokenExchange {

        private GitHubAppTokenProvider provider(final String baseUrl, final Clock clock) throws Exception {
            return new GitHubAppTokenProvider(
                    "123456", "42", testKeyPem(), baseUrl, HttpClient.newHttpClient(), clock);
        }

        private Clock clockAt(final String instant) {
            return Clock.fixed(Instant.parse(instant), ZoneOffset.UTC);
        }

        @Test
        void currentTokenShouldMintInstallationToken(final WireMockRuntimeInfo wm) throws Exception {
            stubFor(post(urlPathEqualTo("/app/installations/42/access_tokens"))
                    .willReturn(aResponse()
                            .withStatus(201)
                            .withHeader("Content-Type", "application/json")
                            .withBody("{\"token\":\"ghs_abc123\",\"expires_at\":\"2026-07-02T13:00:00Z\"}")));

            final String token = provider(wm.getHttpBaseUrl(), clockAt("2026-07-02T12:00:00Z")).currentToken();

            assertThat(token).isEqualTo("ghs_abc123");
            verify(postRequestedFor(urlPathEqualTo("/app/installations/42/access_tokens"))
                    .withHeader("Authorization", matching("Bearer .+"))
                    .withHeader("Accept", equalTo("application/vnd.github+json")));
        }

        @Test
        void currentTokenShouldReuseCachedTokenWithinValidity(final WireMockRuntimeInfo wm) throws Exception {
            stubFor(post(urlPathEqualTo("/app/installations/42/access_tokens"))
                    .willReturn(aResponse()
                            .withStatus(201)
                            .withBody("{\"token\":\"ghs_abc123\",\"expires_at\":\"2026-07-02T13:00:00Z\"}")));

            final var provider = provider(wm.getHttpBaseUrl(), clockAt("2026-07-02T12:00:00Z"));
            provider.currentToken();
            provider.currentToken();

            verify(1, postRequestedFor(urlPathEqualTo("/app/installations/42/access_tokens")));
        }

        @Test
        void currentTokenShouldRemintWhenNearExpiry(final WireMockRuntimeInfo wm) throws Exception {
            stubFor(post(urlPathEqualTo("/app/installations/42/access_tokens"))
                    .inScenario("refresh").whenScenarioStateIs(STARTED)
                    .willReturn(aResponse().withStatus(201)
                            .withBody("{\"token\":\"ghs_first\",\"expires_at\":\"2026-07-02T12:10:00Z\"}"))
                    .willSetStateTo("second"));
            stubFor(post(urlPathEqualTo("/app/installations/42/access_tokens"))
                    .inScenario("refresh").whenScenarioStateIs("second")
                    .willReturn(aResponse().withStatus(201)
                            .withBody("{\"token\":\"ghs_second\",\"expires_at\":\"2026-07-02T13:00:00Z\"}")));

            final var clock = new MutableClock(Instant.parse("2026-07-02T12:00:00Z"));
            final var provider = new GitHubAppTokenProvider(
                    "123456", "42", testKeyPem(), wm.getHttpBaseUrl(), HttpClient.newHttpClient(), clock);

            assertThat(provider.currentToken()).isEqualTo("ghs_first");
            clock.set(Instant.parse("2026-07-02T12:06:00Z")); // within 5-min skew of 12:10 expiry
            assertThat(provider.currentToken()).isEqualTo("ghs_second");

            verify(2, postRequestedFor(urlPathEqualTo("/app/installations/42/access_tokens")));
        }

        @Test
        void currentTokenShouldThrowOnNonCreatedResponse(final WireMockRuntimeInfo wm) throws Exception {
            stubFor(post(urlPathEqualTo("/app/installations/42/access_tokens"))
                    .willReturn(aResponse().withStatus(403).withBody("{\"message\":\"Bad credentials\"}")));

            final var provider = provider(wm.getHttpBaseUrl(), clockAt("2026-07-02T12:00:00Z"));

            assertThatThrownBy(provider::currentToken)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("HTTP 403");
        }

        @Test
        void currentTokenShouldThrowOnMalformedResponseBody(final WireMockRuntimeInfo wm) throws Exception {
            stubFor(post(urlPathEqualTo("/app/installations/42/access_tokens"))
                    .willReturn(aResponse().withStatus(201).withBody("{\"unexpected\":\"shape\"}")));

            final var provider = provider(wm.getHttpBaseUrl(), clockAt("2026-07-02T12:00:00Z"));

            assertThatThrownBy(provider::currentToken)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Unexpected GitHub App token exchange response");
        }
    }

    /** Test clock whose instant can be advanced between calls. */
    private static final class MutableClock extends Clock {
        private Instant instant;

        MutableClock(final Instant instant) {
            this.instant = instant;
        }

        void set(final Instant instant) {
            this.instant = instant;
        }

        @Override
        public Instant instant() {
            return instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(final ZoneId zone) {
            return this;
        }
    }
}
