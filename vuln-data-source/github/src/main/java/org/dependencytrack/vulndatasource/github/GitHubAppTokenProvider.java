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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jspecify.annotations.Nullable;

import static java.util.Objects.requireNonNull;

/**
 * Mints and caches short-lived GitHub App installation access tokens.
 * <p>
 * The cached token is re-minted on access once it comes within {@link #REFRESH_SKEW}
 * of expiry, so a long-running sync that outlives the ~1h token keeps working. No
 * background threads or timers are used.
 */
final class GitHubAppTokenProvider implements GitHubTokenProvider {

    /** Re-mint once the cached token is within this window of its expiry. */
    private static final Duration REFRESH_SKEW = Duration.ofMinutes(5);

    /**
     * Upper bound on the token-exchange request. The interceptor calls
     * {@link #currentToken()} on the async client's I/O thread, so an unbounded
     * request could stall it indefinitely if GitHub's token endpoint hangs.
     */
    private static final Duration TOKEN_EXCHANGE_TIMEOUT = Duration.ofSeconds(10);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final String appId;
    private final String tokenExchangeUrl;
    private final PrivateKey privateKey;
    private final HttpClient httpClient;
    private final Clock clock;

    private @Nullable String cachedToken;
    private @Nullable Instant cachedTokenExpiresAt;

    GitHubAppTokenProvider(
            final String appId,
            final String installationId,
            final String privateKeyPem,
            final String tokenExchangeBaseUrl,
            final HttpClient httpClient,
            final Clock clock) {
        this.appId = appId;
        this.tokenExchangeUrl = tokenExchangeBaseUrl + "/app/installations/" + installationId + "/access_tokens";
        this.privateKey = parsePrivateKey(privateKeyPem);
        this.httpClient = httpClient;
        this.clock = clock;
    }

    /**
     * Derives the token-exchange base URL from the configured GraphQL {@code apiUrl}
     * so GitHub Enterprise Server is supported: {@code api.github.com} maps to
     * {@code https://api.github.com}, any other host to {@code https://<host>/api/v3}.
     */
    static String tokenExchangeBaseUrl(final URI apiUrl) {
        final String origin = apiUrl.getScheme() + "://" + apiUrl.getAuthority();
        return "api.github.com".equals(apiUrl.getHost()) ? origin : origin + "/api/v3";
    }

    @Override
    public synchronized String currentToken() {
        if (cachedToken == null || cachedTokenExpiresAt == null
                || !clock.instant().isBefore(cachedTokenExpiresAt.minus(REFRESH_SKEW))) {
            mint();
        }
        return requireNonNull(cachedToken);
    }

    private void mint() {
        final String appJwt = buildAppJwt(appId, privateKey, clock);
        final HttpRequest request = HttpRequest.newBuilder(URI.create(tokenExchangeUrl))
                .timeout(TOKEN_EXCHANGE_TIMEOUT)
                .header("Authorization", "Bearer " + appJwt)
                .header("Accept", "application/vnd.github+json")
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

        final HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to obtain GitHub App installation token", e);
        }
        if (response.statusCode() != 201) {
            throw new IllegalStateException(
                    "GitHub App token exchange returned HTTP " + response.statusCode() + ": " + response.body());
        }

        final JsonNode body;
        try {
            body = OBJECT_MAPPER.readTree(response.body());
        } catch (Exception e) {
            throw new IllegalStateException("Unexpected GitHub App token exchange response: " + response.body(), e);
        }
        final JsonNode token = body.get("token");
        final JsonNode expiresAt = body.get("expires_at");
        if (token == null || expiresAt == null) {
            throw new IllegalStateException("Unexpected GitHub App token exchange response: " + response.body());
        }
        this.cachedToken = token.asText();
        this.cachedTokenExpiresAt = Instant.parse(expiresAt.asText());
    }

    private static final Pattern PEM_ARMOR = Pattern.compile("-----[^-]+-----|\\s");

    /**
     * Parses an RSA private key in PKCS#8 PEM form ({@code -----BEGIN PRIVATE KEY-----}),
     * which the JDK {@link KeyFactory} reads natively. GitHub delivers App keys in PKCS#1
     * ({@code -----BEGIN RSA PRIVATE KEY-----}); operators convert once with
     * {@code openssl pkcs8 -topk8 -nocrypt}. This keeps key handling to pure JDK with no
     * DER hand-assembly and no BouncyCastle dependency.
     */
    static PrivateKey parsePrivateKey(final String pem) {
        if (pem.contains("RSA PRIVATE KEY")) {
            throw new IllegalArgumentException(
                    "GitHub App private key is in PKCS#1 format (BEGIN RSA PRIVATE KEY); "
                            + "convert it to PKCS#8 with: openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pk8.pem");
        }
        final byte[] pkcs8 = Base64.getDecoder().decode(PEM_ARMOR.matcher(pem).replaceAll(""));
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse GitHub App private key", e);
        }
    }

    /** Clock-skew tolerance subtracted from {@code iat}. */
    private static final long JWT_IAT_SKEW_SECONDS = 60;

    /** Lifetime of the App JWT. GitHub rejects anything over 10 minutes. */
    private static final long JWT_LIFETIME_SECONDS = 300;

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    /**
     * Builds a compact RS256 JWT ({@code header.claims.signature}) asserting the
     * App's identity, signed with the App private key. Used to exchange for an
     * installation access token.
     */
    static String buildAppJwt(final String appId, final PrivateKey privateKey, final Clock clock) {
        final long now = clock.instant().getEpochSecond();
        final String header = URL_ENCODER.encodeToString(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        final String claims = URL_ENCODER.encodeToString(
                ("{\"iss\":\"" + appId + "\",\"iat\":" + (now - JWT_IAT_SKEW_SECONDS)
                        + ",\"exp\":" + (now + JWT_LIFETIME_SECONDS) + "}").getBytes(StandardCharsets.UTF_8));
        final String signingInput = header + "." + claims;
        try {
            final var signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return signingInput + "." + URL_ENCODER.encodeToString(signer.sign());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign GitHub App JWT", e);
        }
    }

}
