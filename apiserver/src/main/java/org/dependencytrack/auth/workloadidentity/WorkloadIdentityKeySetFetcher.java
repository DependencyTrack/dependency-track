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

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetParseException;
import com.nimbusds.jose.jwk.source.JWKSetRetrievalException;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static java.util.Objects.requireNonNull;

/// @since 5.2.0
public final class WorkloadIdentityKeySetFetcher implements ResourceRetriever {

    private static final int MAX_BODY_BYTES = 1048576; // 1MiB

    private final HttpClient httpClient;
    private final boolean relaxedUrlChecks;
    private final Duration fetchTimeout;

    public WorkloadIdentityKeySetFetcher(HttpClient httpClient) {
        this(httpClient, /* relaxedUrlChecks */ false, Duration.ofSeconds(10));
    }

    WorkloadIdentityKeySetFetcher(HttpClient httpClient, boolean relaxedUrlChecks, Duration fetchTimeout) {
        this.httpClient = requireNonNull(httpClient, "httpClient must not be null");
        if (httpClient.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("httpClient must not follow redirects");
        }
        this.relaxedUrlChecks = relaxedUrlChecks;
        this.fetchTimeout = requireNonNull(fetchTimeout, "fetchTimeout must not be null");
    }

    public JWKSet fetchKeySet(String url) throws KeySourceException, InterruptedException {
        return parsePublicKeySet(fetch(requireValidUrl(url), "Key set"));
    }

    public static JWKSet parsePublicKeySet(String json) throws JWKSetParseException {
        final JWKSet keySet;
        try {
            keySet = JWKSet.parse(json);
        } catch (java.text.ParseException e) {
            throw new JWKSetParseException("Key set is not a valid JSON Web Key Set", e);
        }

        if (keySet.isEmpty()) {
            throw new JWKSetParseException("Key set does not contain any key", null);
        }
        if (keySet.containsNonPublicKeys()) {
            throw new JWKSetParseException("Key set must only contain public keys", null);
        }

        return keySet;
    }

    @Override
    public Resource retrieveResource(URL url) throws IOException {
        try {
            return new Resource(fetch(requireValidUrl(url.toString()), "Key set"), "application/json");
        } catch (JWKSetRetrievalException e) {
            throw new IOException(e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException(e.getMessage());
        }
    }

    public String resolveJwksUri(String issuer) throws KeySourceException, GeneralException, InterruptedException {
        final URI discoveryUri = requireValidUrl(issuer.replaceAll("/+$", "") + "/.well-known/openid-configuration");
        final String body = fetch(discoveryUri, "Discovery document");

        final AuthorizationServerMetadata metadata;
        try {
            metadata = AuthorizationServerMetadata.parse(body);
        } catch (ParseException e) {
            throw new ParseException("Discovery document is not valid", e);
        }

        if (!issuer.equals(metadata.getIssuer().getValue())) {
            throw new GeneralException("Discovery document names another issuer");
        }
        if (metadata.getJWKSetURI() == null) {
            throw new GeneralException("Discovery document does not name a jwks_uri");
        }

        return requireValidUrl(metadata.getJWKSetURI().toString()).toString();
    }

    private String fetch(URI uri, String what) throws JWKSetRetrievalException, InterruptedException {
        final var request = HttpRequest.newBuilder()
                .uri(uri)
                .header("Accept", "application/json")
                .GET()
                .build();

        // NB: The request timeout stops counting once the response headers arrive.
        // The future only completes with the whole body, so waiting on it captures the body read as well.
        final CompletableFuture<HttpResponse<byte[]>> future = httpClient.sendAsync(
                request, HttpResponse.BodyHandlers.limiting(HttpResponse.BodyHandlers.ofByteArray(), MAX_BODY_BYTES));

        final HttpResponse<byte[]> response;
        try {
            response = future.get(fetchTimeout.toNanos(), TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            future.cancel(true);
            throw e;
        } catch (TimeoutException | ExecutionException e) {
            future.cancel(true);
            throw new JWKSetRetrievalException(
                    "%s is unreachable, or larger than %d bytes".formatted(what, MAX_BODY_BYTES), e);
        }
        if (response.statusCode() != 200) {
            throw new JWKSetRetrievalException(
                    "%s is unreachable (HTTP %d)".formatted(what, response.statusCode()), null);
        }

        return new String(response.body(), StandardCharsets.UTF_8);
    }

    private URI requireValidUrl(String url) throws JWKSetRetrievalException {
        final URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new JWKSetRetrievalException("%s is not a valid URL".formatted(url), null);
        }

        if (!relaxedUrlChecks && !"https".equalsIgnoreCase(uri.getScheme())) {
            throw new JWKSetRetrievalException("Only https URLs are allowed", null);
        }
        if (uri.getUserInfo() != null) {
            throw new JWKSetRetrievalException("URLs with user information are not allowed", null);
        }

        final String host = uri.getHost();
        if (host == null) {
            throw new JWKSetRetrievalException("%s is not a valid URL".formatted(url), null);
        }
        if (relaxedUrlChecks
                // NB: Local lookup is meaningless if the configured proxy resolves the address.
                || isProxied(uri)) {
            return uri;
        }

        final InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new JWKSetRetrievalException("Host %s cannot be resolved".formatted(host), e);
        }

        // Private ranges are allowed on purpose, since internal issuers are a supported deployment.
        for (final InetAddress address : addresses) {
            if (address.isLoopbackAddress()
                    || address.isLinkLocalAddress()
                    || address.isAnyLocalAddress()
                    || address.isMulticastAddress()) {
                throw new JWKSetRetrievalException("Connections to host %s are not allowed".formatted(host), null);
            }
        }

        return uri;
    }

    private boolean isProxied(URI uri) {
        return httpClient
                .proxy()
                .map(proxySelector ->
                        proxySelector.select(uri).stream().anyMatch(proxy -> proxy.type() != Proxy.Type.DIRECT))
                .orElse(false);
    }
}
