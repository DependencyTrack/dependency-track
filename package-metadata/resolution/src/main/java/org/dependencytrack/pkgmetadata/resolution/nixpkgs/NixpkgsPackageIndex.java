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
package org.dependencytrack.pkgmetadata.resolution.nixpkgs;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import org.brotli.dec.BrotliInputStream;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

final class NixpkgsPackageIndex {

    private record IndexEntry(Map<String, String> versionByName, Instant lastRefreshed) {
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(NixpkgsPackageIndex.class);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration REFRESH_INTERVAL = Duration.ofMinutes(60);
    private static final int MAX_CACHED_URLS = 3;

    private final HttpClient httpClient;
    private final JsonFactory jsonFactory;
    private final ReentrantLock downloadLock = new ReentrantLock();

    private volatile Map<String, IndexEntry> indexEntryByRepoUrl = Map.of();

    NixpkgsPackageIndex(HttpClient httpClient, JsonFactory jsonFactory) {
        this.httpClient = httpClient;
        this.jsonFactory = jsonFactory;
    }

    @Nullable String getVersion(String pname, String repoUrl) throws InterruptedException {
        ensureFresh(repoUrl);

        final IndexEntry entry = indexEntryByRepoUrl.get(repoUrl);
        if (entry == null) {
            return null;
        }

        return entry.versionByName().get(pname);
    }

    private static boolean isFresh(@Nullable IndexEntry entry) {
        return entry != null
                && Duration.between(entry.lastRefreshed(), Instant.now()).compareTo(REFRESH_INTERVAL) < 0;
    }

    private void ensureFresh(String repoUrl) throws InterruptedException {
        if (isFresh(indexEntryByRepoUrl.get(repoUrl))) {
            return;
        }

        downloadLock.lockInterruptibly();
        try {
            if (isFresh(indexEntryByRepoUrl.get(repoUrl))) {
                return;
            }

            final Map<String, String> newVersionByName = downloadAndParse(repoUrl);

            // Prevent unbounded memory consumption by enforcing a limit of
            // how many indexes we cache. This is not optimal, but the lack
            // of a true registry API for Nix makes it the only sane option.
            // We expect most users to configure at most one Nix repository.
            final var newEntries = new LinkedHashMap<String, IndexEntry>(MAX_CACHED_URLS + 1, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, IndexEntry> eldest) {
                    return size() > MAX_CACHED_URLS;
                }
            };

            newEntries.putAll(indexEntryByRepoUrl);
            newEntries.put(repoUrl, new IndexEntry(newVersionByName, Instant.now()));
            indexEntryByRepoUrl = Collections.unmodifiableMap(newEntries);
            LOGGER.debug("Loaded {} nixpkgs package versions from {}", newVersionByName.size(), repoUrl);
        } finally {
            downloadLock.unlock();
        }
    }

    private Map<String, String> downloadAndParse(String url) throws InterruptedException {
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        final HttpResponse<InputStream> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (HttpTimeoutException e) {
            throw new RetryableResolutionException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        try (final InputStream body = response.body()) {
            RetryableResolutionException.throwIfRetryableError(response, Clock.systemUTC());
            if (response.statusCode() != 200) {
                throw new UncheckedIOException(new IOException(
                        "Unexpected status code %d for %s".formatted(response.statusCode(), url)));
            }

            try (final var brotliStream = new BrotliInputStream(body);
                 final JsonParser parser = jsonFactory.createParser(brotliStream)) {
                return parsePackages(parser);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private Map<String, String> parsePackages(JsonParser parser) throws IOException {
        final var versionByName = new HashMap<String, String>();

        parser.nextToken();
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            final String fieldName = parser.currentName();
            final JsonToken token = parser.nextToken();

            if ("packages".equals(fieldName) && token == JsonToken.START_OBJECT) {
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    parser.nextToken();
                    final JsonNode packageNode = parser.readValueAsTree();
                    final JsonNode pnameNode = packageNode.get("pname");
                    final JsonNode versionNode = packageNode.get("version");

                    if (pnameNode != null && versionNode != null) {
                        versionByName.putIfAbsent(pnameNode.asText(), versionNode.asText());
                    }
                }
            } else {
                parser.skipChildren();
            }
        }

        return versionByName;
    }

}
