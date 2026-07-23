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

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * @since 5.0.0
 */
final class HttpNotificationResponseBodies {

    private static final int DISCARD_BUFFER_SIZE = 8192;

    private HttpNotificationResponseBodies() {
    }

    static String readSnippetAndDiscardRemainder(final InputStream body, final int maxChars) throws IOException {
        if (body == null) {
            return "";
        }

        try (var reader = new InputStreamReader(body, StandardCharsets.UTF_8)) {
            final var snippetBuffer = new char[maxChars];
            int snippetLength = 0;
            int read;
            while (snippetLength < maxChars && (read = reader.read(snippetBuffer, snippetLength, maxChars - snippetLength)) != -1) {
                snippetLength += read;
            }

            final var discardBuffer = new char[DISCARD_BUFFER_SIZE];
            while (reader.read(discardBuffer) != -1) {
                // Discard the remainder so the connection can be reused.
            }

            return new String(snippetBuffer, 0, snippetLength);
        }
    }

    static void discardRemainder(final InputStream body) throws IOException {
        if (body != null) {
            body.transferTo(OutputStream.nullOutputStream());
        }
    }

}
