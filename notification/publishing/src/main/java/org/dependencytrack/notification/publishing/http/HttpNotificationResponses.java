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
package org.dependencytrack.notification.publishing.http;

import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.support.net.HttpRetry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Writer;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

/**
 * @since 5.1.0
 */
public final class HttpNotificationResponses {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpNotificationResponses.class);

    static final int WARN_BODY_SNIPPET_LENGTH = 100;
    static final int DEBUG_BODY_SNIPPET_LENGTH = 1000;

    private HttpNotificationResponses() {}

    public static void ensureSuccessful2xxResponse(final HttpResponse<InputStream> response) throws IOException {
        try (InputStream body = response.body()) {
            final HttpRetry retry = HttpRetry.of(response);
            if (retry.isRetryable()) {
                final String bodySnippet = readSnippetAndDiscardRemainder(body, DEBUG_BODY_SNIPPET_LENGTH);
                logWarnWithResponseBody(retry.description(), bodySnippet);
                throw new RetryablePublishException(retry.description(), null, retry.retryAfter());
            }

            final int statusCode = response.statusCode();
            if (statusCode < 200 || statusCode > 299) {
                final String message = "Request failed with unexpected response code: " + statusCode;
                final String bodySnippet = readSnippetAndDiscardRemainder(body, DEBUG_BODY_SNIPPET_LENGTH);
                logErrorWithResponseBody(message, bodySnippet);
                throw new IllegalStateException(message);
            }

            discardRemainder(body);
        }
    }

    public static void ensureStatusCode(
            final HttpResponse<InputStream> response, final int expectedStatusCode, final String failureMessagePrefix)
            throws IOException {
        if (response.statusCode() == expectedStatusCode) {
            try (InputStream body = response.body()) {
                discardRemainder(body);
            }
            return;
        }

        try (InputStream body = response.body()) {
            final String message = failureMessagePrefix + response.statusCode();
            final String bodySnippet = readSnippetAndDiscardRemainder(body, DEBUG_BODY_SNIPPET_LENGTH);
            logErrorWithResponseBody(message, bodySnippet);
            throw new IllegalStateException(message);
        }
    }

    static String truncate(final String value, final int maxLength) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    private static String readSnippetAndDiscardRemainder(final InputStream body, final int maxChars)
            throws IOException {
        if (body == null) {
            return "";
        }

        try (var reader = new InputStreamReader(body, StandardCharsets.UTF_8)) {
            final var snippetBuffer = new char[maxChars];
            int snippetLength = 0;
            int read;
            while (snippetLength < maxChars
                    && (read = reader.read(snippetBuffer, snippetLength, maxChars - snippetLength)) != -1) {
                snippetLength += read;
            }

            reader.transferTo(Writer.nullWriter());

            return new String(snippetBuffer, 0, snippetLength);
        }
    }

    private static void discardRemainder(final InputStream body) throws IOException {
        if (body != null) {
            body.transferTo(OutputStream.nullOutputStream());
        }
    }

    private static void logWarnWithResponseBody(final String message, final String responseBody) {
        LOGGER.warn("{}; response body: {}", message, truncate(responseBody, WARN_BODY_SNIPPET_LENGTH));
        logDebugResponseBody(responseBody);
    }

    private static void logErrorWithResponseBody(final String message, final String responseBody) {
        LOGGER.error("{}; response body: {}", message, truncate(responseBody, WARN_BODY_SNIPPET_LENGTH));
        logDebugResponseBody(responseBody);
    }

    private static void logDebugResponseBody(final String responseBody) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Response body: {}", truncate(responseBody, DEBUG_BODY_SNIPPET_LENGTH));
        }
    }
}
