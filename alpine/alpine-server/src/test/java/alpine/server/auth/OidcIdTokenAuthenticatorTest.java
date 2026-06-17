/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */

package alpine.server.auth;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.PlainObject;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.RestoreEnvironmentVariables;
import org.junitpioneer.jupiter.SetEnvironmentVariable;
import wiremock.org.apache.hc.core5.http.ContentType;
import wiremock.org.apache.hc.core5.http.HttpHeaders;
import wiremock.org.apache.hc.core5.http.HttpStatus;

import java.net.ConnectException;
import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@WireMockTest
public class OidcIdTokenAuthenticatorTest {

    private static final String USERNAME_CLAIM_NAME = "username";
    private static final String TEAMS_CLAIM_NAME = "groups";
    private static final String EMAIL_CLAIM_NAME = "email";
    private static final OidcProfileCreator PROFILE_CREATOR = claims -> {
        final var profile = new OidcProfile();
        profile.setSubject(claims.getStringClaim(IDTokenClaimsSet.SUB_CLAIM_NAME));
        profile.setUsername(claims.getStringClaim(USERNAME_CLAIM_NAME));
        profile.setGroups(claims.getStringListClaim(TEAMS_CLAIM_NAME));
        profile.setEmail(claims.getStringClaim(EMAIL_CLAIM_NAME));
        return profile;
    };

    private OidcConfiguration oidcConfiguration;

    @BeforeEach
    public void setUp() {
        oidcConfiguration = new OidcConfiguration();
    }

    @AfterEach
    public void tearDown() {
        OidcIdTokenAuthenticator.resetCache();
    }

    @Test
    public void authenticateShouldReturnOidcProfile(final WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Generate a JWK to sign the token with
        final RSAKey jwk = new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE).keyID(UUID.randomUUID().toString()).generate();
        final var jwkSet = new JWKSet(jwk.toPublicJWK());

        // Register endpoint for JWK set retrieval
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/jwks"))
                .willReturn(WireMock.aResponse()
                        .withStatus(HttpStatus.SC_OK)
                        .withHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                        .withBody(jwkSet.toString())));

        oidcConfiguration.setIssuer(wmRuntimeInfo.getHttpBaseUrl());
        oidcConfiguration.setJwksUri(new URI(wmRuntimeInfo.getHttpBaseUrl() + "/jwks"));

        // Construct a JWS object with all required claims
        final var token = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID()).build(),
                new Payload(Map.of(
                        IDTokenClaimsSet.SUB_CLAIM_NAME, "subject",
                        IDTokenClaimsSet.AUD_CLAIM_NAME, "clientId",
                        IDTokenClaimsSet.ISS_CLAIM_NAME, wmRuntimeInfo.getHttpBaseUrl(),
                        IDTokenClaimsSet.EXP_CLAIM_NAME, LocalDateTime.now().plusMinutes(1).atZone(ZoneId.systemDefault()).toEpochSecond(),
                        IDTokenClaimsSet.IAT_CLAIM_NAME, LocalDateTime.now().minusMinutes(1).atZone(ZoneId.systemDefault()).toEpochSecond(),
                        USERNAME_CLAIM_NAME, "username",
                        TEAMS_CLAIM_NAME, List.of("group1", "group2"),
                        EMAIL_CLAIM_NAME, "username@example.com"
                ))
        );

        // Sign the object
        final var signer = new RSASSASigner(jwk);
        token.sign(signer);

        final var authenticator = new OidcIdTokenAuthenticator(oidcConfiguration, "clientId");

        final OidcProfile profile = authenticator.authenticate(token.serialize(), PROFILE_CREATOR);
        assertThat(profile.getSubject()).isEqualTo("subject");
        assertThat(profile.getUsername()).isEqualTo("username");
        assertThat(profile.getGroups()).containsExactly("group1", "group2");
        assertThat(profile.getEmail()).isEqualTo("username@example.com");
    }

    @Test
    public void authenticateShouldThrowWhenTokenIsNotSigned(final WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Generate a JWK to sign the token with
        final RSAKey jwk = new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE).keyID(UUID.randomUUID().toString()).generate();
        final var jwkSet = new JWKSet(jwk.toPublicJWK());

        // Register endpoint for JWK set retrieval
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/jwks"))
                .willReturn(WireMock.aResponse()
                        .withStatus(HttpStatus.SC_OK)
                        .withHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                        .withBody(jwkSet.toString())));

        oidcConfiguration.setIssuer(wmRuntimeInfo.getHttpBaseUrl());
        oidcConfiguration.setJwksUri(new URI(wmRuntimeInfo.getHttpBaseUrl() + "/jwks"));

        // Construct an unsigned token with all required claims
        final var token = new PlainObject(
                new Payload(Map.of(
                        IDTokenClaimsSet.SUB_CLAIM_NAME, "subject",
                        IDTokenClaimsSet.AUD_CLAIM_NAME, "clientId",
                        IDTokenClaimsSet.ISS_CLAIM_NAME, wmRuntimeInfo.getHttpBaseUrl(),
                        IDTokenClaimsSet.EXP_CLAIM_NAME, LocalDateTime.now().plusMinutes(1).atZone(ZoneId.systemDefault()).toEpochSecond(),
                        IDTokenClaimsSet.IAT_CLAIM_NAME, LocalDateTime.now().minusMinutes(1).atZone(ZoneId.systemDefault()).toEpochSecond()
                ))
        );

        final var authenticator = new OidcIdTokenAuthenticator(oidcConfiguration, "clientId");

        // Try to authenticate using the unsigned token
        Assertions.assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(() -> authenticator.authenticate(token.serialize(), PROFILE_CREATOR))
                .satisfies(exception -> assertThat(exception.getCauseType())
                        .isEqualTo(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS));
    }

    @Test
    public void authenticateShouldThrowWhenResolvingJwkSetFailed(final WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Register endpoint for JWK set retrieval
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/jwks"))
                .willReturn(WireMock.aResponse()
                        .withStatus(HttpStatus.SC_NOT_FOUND)));

        oidcConfiguration.setIssuer(wmRuntimeInfo.getHttpBaseUrl());
        oidcConfiguration.setJwksUri(new URI(wmRuntimeInfo.getHttpBaseUrl() + "/jwks"));

        // Generate a JWK to sign the token with
        final RSAKey jwk = new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE).keyID(UUID.randomUUID().toString()).generate();

        // Construct a JWS object with all required claims
        final var token = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID()).build(),
                new Payload(Map.of(
                        IDTokenClaimsSet.SUB_CLAIM_NAME, "subject",
                        IDTokenClaimsSet.AUD_CLAIM_NAME, "clientId",
                        IDTokenClaimsSet.ISS_CLAIM_NAME, wmRuntimeInfo.getHttpBaseUrl(),
                        IDTokenClaimsSet.EXP_CLAIM_NAME, LocalDateTime.now().plusMinutes(1).atZone(ZoneId.systemDefault()).toEpochSecond(),
                        IDTokenClaimsSet.IAT_CLAIM_NAME, LocalDateTime.now().minusMinutes(1).atZone(ZoneId.systemDefault()).toEpochSecond()
                ))
        );

        // Sign the object
        final var signer = new RSASSASigner(jwk);
        token.sign(signer);

        final var authenticator = new OidcIdTokenAuthenticator(oidcConfiguration, "clientId");

        // Try to authenticate
        Assertions.assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(() -> authenticator.authenticate(token.serialize(), PROFILE_CREATOR))
                .satisfies(exception -> assertThat(exception.getCauseType())
                        .isEqualTo(AlpineAuthenticationException.CauseType.OTHER));
    }

    @Test
    public void authenticateShouldThrowWhenValidatingIdTokenFailed(final WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Generate a JWK to sign the token with
        final RSAKey jwk = new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE).keyID(UUID.randomUUID().toString()).generate();
        final var jwkSet = new JWKSet(jwk.toPublicJWK());

        // Register endpoint for JWK set retrieval
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/jwks"))
                .willReturn(WireMock.aResponse()
                        .withStatus(HttpStatus.SC_OK)
                        .withHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                        .withBody(jwkSet.toString())));

        oidcConfiguration.setIssuer(wmRuntimeInfo.getHttpBaseUrl());
        oidcConfiguration.setJwksUri(new URI(wmRuntimeInfo.getHttpBaseUrl() + "/jwks"));

        // Construct a JWS object with all required claims
        final var token = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID()).build(),
                new Payload(Map.of(
                        IDTokenClaimsSet.SUB_CLAIM_NAME, "subject",
                        IDTokenClaimsSet.AUD_CLAIM_NAME, "clientId",
                        IDTokenClaimsSet.ISS_CLAIM_NAME, wmRuntimeInfo.getHttpBaseUrl(),
                        IDTokenClaimsSet.EXP_CLAIM_NAME, LocalDateTime.now().plusMinutes(1).atZone(ZoneId.systemDefault()).toEpochSecond(),
                        IDTokenClaimsSet.IAT_CLAIM_NAME, LocalDateTime.now().minusMinutes(1).atZone(ZoneId.systemDefault()).toEpochSecond()
                ))
        );

        // Use a different key to sign the object
        final RSAKey signingKey = new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE).keyID(UUID.randomUUID().toString()).generate();
        final var signer = new RSASSASigner(signingKey);
        token.sign(signer);

        final var authenticator = new OidcIdTokenAuthenticator(oidcConfiguration, "clientId");

        // Try to authenticate. Should fail because signature can't be verified
        Assertions.assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(() -> authenticator.authenticate(token.serialize(), PROFILE_CREATOR))
                .satisfies(exception -> assertThat(exception.getCauseType())
                        .isEqualTo(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS));
    }

    @Test
    public void resolveJwkSetShouldReturnCachedValueWhenAvailable() throws Exception {
        final var cachedJwkSet = new JWKSet();
        OidcIdTokenAuthenticator.seedCache(cachedJwkSet);

        final var authenticator = new OidcIdTokenAuthenticator(oidcConfiguration, "clientId");
        assertThat(authenticator.resolveJwkSet()).isEqualTo(cachedJwkSet);
    }

    @Test
    public void resolveJwkSetShouldReturnJwkSetAndStoreItInCache(final WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/jwks"))
                .willReturn(WireMock.aResponse()
                        .withStatus(HttpStatus.SC_OK)
                        .withHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                        // This JWK set is taken from https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1
                        .withBody("" +
                                "{\n" +
                                "  \"keys\": [\n" +
                                "    {\n" +
                                "      \"kty\": \"EC\",\n" +
                                "      \"crv\": \"P-256\",\n" +
                                "      \"x\": \"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\n" +
                                "      \"y\": \"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\n" +
                                "      \"use\": \"enc\",\n" +
                                "      \"kid\": \"1\"\n" +
                                "    },\n" +
                                "    {\n" +
                                "      \"kty\": \"RSA\",\n" +
                                "      \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
                                "      \"e\": \"AQAB\",\n" +
                                "      \"alg\": \"RS256\",\n" +
                                "      \"kid\": \"2011-04-29\"\n" +
                                "    }\n" +
                                "  ]\n" +
                                "}")));

        oidcConfiguration.setJwksUri(new URI(wmRuntimeInfo.getHttpBaseUrl() + "/jwks"));

        final var authenticator = new OidcIdTokenAuthenticator(oidcConfiguration, "clientId");

        // Resolve and verify JWK set
        final JWKSet jwkSet = authenticator.resolveJwkSet();
        Assertions.assertThat(jwkSet.getKeys()).hasSize(2);
        Assertions.assertThat(jwkSet.getKeyByKeyId("1").getKeyType()).isEqualTo(KeyType.EC);
        Assertions.assertThat(jwkSet.getKeyByKeyId("2011-04-29").getKeyType()).isEqualTo(KeyType.RSA);

        // On the next invocation, the JWK set should be loaded from cache
        assertThat(authenticator.resolveJwkSet()).isEqualTo(jwkSet);

        // Only one request should've been made
        WireMock.verify(1, WireMock.getRequestedFor(WireMock.urlPathEqualTo("/jwks")));
    }

    @Test
    @RestoreEnvironmentVariables
    @SetEnvironmentVariable(key = "http_proxy", value = "http://localhost:6666")
    public void resolveJwkSetShouldUseHttpProxyIfConfigured(final WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/jwks"))
                .willReturn(WireMock.aResponse()
                        .withStatus(418)));

        oidcConfiguration.setJwksUri(new URI(wmRuntimeInfo.getHttpBaseUrl() + "/jwks"));

        final var authenticator = new OidcIdTokenAuthenticator(oidcConfiguration, "clientId");

        // Attempt to resolve the JWK set.
        // Should try to use the configured HTTP proxy, which will fail.
        assertThatExceptionOfType(ConnectException.class)
                .isThrownBy(authenticator::resolveJwkSet);

        // No request should've reached its target.
        WireMock.verify(0, WireMock.getRequestedFor(WireMock.urlPathEqualTo("/jwks")));
    }

}