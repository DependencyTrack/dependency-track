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

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/// Loads the SAML metadata of the identity provider, and caches it.
///
/// When loading fails after the cache expired, the cached metadata stays in use.
///
/// @since 5.3.0
public final class SamlIdpMetadataProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlIdpMetadataProvider.class);
    private static final Duration CACHE_DURATION = Duration.ofHours(1);
    private static final Duration RETRY_DELAY = Duration.ofMinutes(1);
    private static final Duration FETCH_TIMEOUT = Duration.ofSeconds(10);
    private static final int MAX_METADATA_BYTES = 1024 * 1024;

    private final @Nullable URI metadataUrl;
    private final @Nullable Path metadataFile;
    private final HttpClient httpClient;
    private final Clock clock;
    private @Nullable SamlIdpMetadata cached;
    private Instant nextRefreshAt = Instant.MIN;

    SamlIdpMetadataProvider(
            @Nullable URI metadataUrl, @Nullable Path metadataFile, HttpClient httpClient, Clock clock) {
        this.metadataUrl = metadataUrl;
        this.metadataFile = metadataFile;
        this.httpClient = httpClient;
        this.clock = clock;
    }

    public SamlIdpMetadataProvider(SamlConfig config) {
        this(
                config.idpMetadataUrl(),
                config.idpMetadataFile(),
                org.dependencytrack.common.HttpClient.INSTANCE,
                Clock.systemUTC());
    }

    /// @throws SamlException When no metadata could be loaded so far.
    public synchronized SamlIdpMetadata get() throws SamlException {
        final Instant now = clock.instant();
        if (cached != null && now.isBefore(nextRefreshAt)) {
            return cached;
        }

        try {
            cached = SamlIdpMetadata.parse(load());
            nextRefreshAt = now.plus(CACHE_DURATION);
            return cached;
        } catch (SamlException | IOException | IllegalArgumentException e) {
            nextRefreshAt = now.plus(RETRY_DELAY);
            if (cached != null) {
                LOGGER.warn("Failed to refresh SAML identity provider metadata; Using cached metadata", e);
                return cached;
            }
            throw new SamlException("Failed to load SAML identity provider metadata", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SamlException("Interrupted while loading SAML identity provider metadata", e);
        }
    }

    private byte[] load() throws IOException, InterruptedException {
        if (metadataFile != null) {
            if (Files.size(metadataFile) > MAX_METADATA_BYTES) {
                throw new IOException("Metadata file exceeds %d bytes".formatted(MAX_METADATA_BYTES));
            }
            return Files.readAllBytes(metadataFile);
        }
        if (metadataUrl == null) {
            throw new IllegalStateException("Neither metadata URL nor file configured");
        }

        final HttpResponse<byte[]> response = httpClient.send(
                HttpRequest.newBuilder(metadataUrl).timeout(FETCH_TIMEOUT).GET().build(),
                HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new IOException("Unexpected response code %d from %s".formatted(response.statusCode(), metadataUrl));
        }
        if (response.body().length > MAX_METADATA_BYTES) {
            throw new IOException("Metadata exceeds %d bytes".formatted(MAX_METADATA_BYTES));
        }
        return response.body();
    }
}
