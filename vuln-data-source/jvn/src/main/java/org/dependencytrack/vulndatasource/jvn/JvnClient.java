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
package org.dependencytrack.vulndatasource.jvn;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * A thin client for the JVN data feeds published under {@code https://jvndb.jvn.jp/ja/feed}.
 * <p>
 * Fetches the per-year detail feeds ({@code detail/jvndb_detail_YYYY.rdf}, full history 1988–present)
 * and the {@code checksum.txt} manifest used to skip years whose feed has not changed. This is the
 * same acquisition strategy used by go-cve-dictionary / Vuls, and — unlike the MyJVN
 * {@code getVulnOverviewList} API — is not capped to the most-recent advisories.
 *
 * @since 5.1.0
 */
final class JvnClient {

    static final String DEFAULT_FEED_BASE_URL = "https://jvndb.jvn.jp/ja/feed";

    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpClient httpClient;
    private final String feedBaseUrl;

    JvnClient(final HttpClient httpClient, final String feedBaseUrl) {
        this.httpClient = httpClient;
        this.feedBaseUrl = feedBaseUrl.endsWith("/")
                ? feedBaseUrl.substring(0, feedBaseUrl.length() - 1)
                : feedBaseUrl;
    }

    /** Downloads the full detail feed (a VULDEF document) for a single publication year. */
    byte[] fetchDetailFeed(final int year) throws IOException, InterruptedException {
        return get(feedBaseUrl + "/detail/" + detailFeedFilename(year));
    }

    /**
     * Fetches {@code checksum.txt} and returns a map of feed filename to its {@code sha256} digest,
     * so callers can skip re-downloading years whose feed is unchanged since the last run.
     */
    Map<String, String> fetchChecksums() throws IOException, InterruptedException {
        final JsonNode array = JSON.readTree(get(feedBaseUrl + "/checksum.txt"));
        final Map<String, String> digestByFilename = new HashMap<>();
        if (array.isArray()) {
            for (final JsonNode entry : array) {
                final String filename = entry.path("filename").asText(null);
                final String sha256 = entry.path("sha256").asText(null);
                if (filename != null && sha256 != null) {
                    digestByFilename.put(filename, sha256);
                }
            }
        }
        return digestByFilename;
    }

    /** The {@code checksum.txt} filename for a year's detail feed (e.g. {@code jvndb_detail_2015.rdf}). */
    static String detailFeedFilename(final int year) {
        return "jvndb_detail_" + year + ".rdf";
    }

    String feedBaseUrl() {
        return feedBaseUrl;
    }

    private byte[] get(final String url) throws IOException, InterruptedException {
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .header("User-Agent", "Dependency-Track JVN data source")
                .GET()
                .build();
        final HttpResponse<byte[]> response = httpClient.send(request, BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new IOException("Unexpected response code " + response.statusCode()
                    + " from JVN feed: " + url);
        }
        return response.body();
    }
}
