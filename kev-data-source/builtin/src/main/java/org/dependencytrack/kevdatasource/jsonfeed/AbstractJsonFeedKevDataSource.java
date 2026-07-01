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
package org.dependencytrack.kevdatasource.jsonfeed;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.kevdatasource.api.KevDataSource;
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
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.Iterator;
import java.util.List;

/// KEV data source whose entire feed is served as a single JSON feed file.
///
/// @since 5.1.0
public abstract class AbstractJsonFeedKevDataSource implements KevDataSource {

    private static final Duration REQUEST_TIMEOUT = Duration.ofMinutes(1);

    private final HttpClient httpClient;
    protected final ObjectMapper objectMapper;
    private final URI feedUrl;
    private final Logger logger;
    private @Nullable Iterator<KevAssertion> delegate;

    protected AbstractJsonFeedKevDataSource(
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI feedUrl) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.feedUrl = feedUrl;
        this.logger = LoggerFactory.getLogger(this.getClass());
    }

    @Override
    public boolean hasNext() {
        return iterator().hasNext();
    }

    @Override
    public KevAssertion next() {
        return iterator().next();
    }

    private Iterator<KevAssertion> iterator() {
        if (delegate == null) {
            delegate = fetchKevFeed().iterator();
        }

        return delegate;
    }

    private List<KevAssertion> fetchKevFeed() {
        final HttpResponse<InputStream> response;
        try {
            logger.debug("Fetching feed from {}", feedUrl);
            response = httpClient.send(
                    HttpRequest.newBuilder(feedUrl)
                            .timeout(REQUEST_TIMEOUT)
                            .GET()
                            .build(),
                    BodyHandlers.ofInputStream());
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to request feed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while downloading feed", e);
        }

        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "Requesting feed failed with unexpected response code: "
                            + response.statusCode());
        }

        try (final InputStream body = response.body()) {
            logger.debug("Parsing KEV assertions from feed");
            return parseKevAssertions(body);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to parse feed", e);
        }
    }

    private List<KevAssertion> parseKevAssertions(InputStream inputStream) throws IOException {
        try (final JsonParser jsonParser = objectMapper.getFactory().createParser(inputStream)) {
            return parseEntries(jsonParser);
        }
    }

    protected abstract List<KevAssertion> parseEntries(JsonParser jsonParser) throws IOException;

}
