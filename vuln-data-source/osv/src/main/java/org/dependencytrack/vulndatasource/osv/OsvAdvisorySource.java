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
package org.dependencytrack.vulndatasource.osv;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.vulndatasource.osv.schema.Osv;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static java.util.function.Predicate.not;
import static org.dependencytrack.vulndatasource.osv.OsvEcosystems.encodeEcosystem;

/**
 * @since 5.0.0
 */
sealed interface OsvAdvisorySource extends Iterator<Osv>, Closeable {

    final class ZipOsvAdvisorySource implements OsvAdvisorySource {

        private final Path zipFilePath;
        private final ObjectMapper objectMapper;
        private final ZipFile zipFile;
        private final Iterator<? extends ZipEntry> entryIterator;

        ZipOsvAdvisorySource(Path zipFilePath, ObjectMapper objectMapper) throws IOException {
            this.zipFilePath = zipFilePath;
            this.objectMapper = objectMapper;
            this.zipFile = new ZipFile(zipFilePath.toFile());
            this.entryIterator = zipFile.stream()
                    .filter(not(ZipEntry::isDirectory))
                    .filter(entry -> entry.getName().endsWith(".json"))
                    .iterator();
        }

        @Override
        public boolean hasNext() {
            return entryIterator.hasNext();
        }

        @Override
        public Osv next() {
            final ZipEntry entry = entryIterator.next();
            try (final InputStream inputStream = zipFile.getInputStream(entry)) {
                return objectMapper.readValue(inputStream, Osv.class);
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to read OSV advisory " + entry.getName(), e);
            }
        }

        @Override
        public void close() throws IOException {
            try {
                zipFile.close();
            } finally {
                Files.deleteIfExists(zipFilePath);
            }
        }

    }

    final class IncrementalOsvAdvisorySource implements OsvAdvisorySource {

        private static final Logger LOGGER = LoggerFactory.getLogger(IncrementalOsvAdvisorySource.class);

        private final HttpClient httpClient;
        private final ObjectMapper objectMapper;
        private final String dataUrl;
        private final String ecosystem;
        private final Iterator<String> advisoryIdIterator;

        IncrementalOsvAdvisorySource(
                HttpClient httpClient,
                ObjectMapper objectMapper,
                String dataUrl,
                String ecosystem,
                Set<String> advisoryIds) {
            this.httpClient = httpClient;
            this.objectMapper = objectMapper;
            this.dataUrl = dataUrl;
            this.ecosystem = ecosystem;
            this.advisoryIdIterator = Set.copyOf(advisoryIds).iterator();
        }

        @Override
        public boolean hasNext() {
            return advisoryIdIterator.hasNext();
        }

        @Override
        public Osv next() {
            final String advisoryId = advisoryIdIterator.next();
            LOGGER.debug("Downloading advisory {}", advisoryId);

            final var request = HttpRequest.newBuilder()
                    .uri(URI.create("%s/%s/%s.json".formatted(dataUrl, encodeEcosystem(ecosystem), advisoryId)))
                    .GET()
                    .build();

            final HttpResponse<byte[]> response;
            try {
                response = httpClient.send(request, BodyHandlers.ofByteArray());
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to download OSV advisory " + advisoryId, e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while downloading OSV advisory " + advisoryId, e);
            }
            if (response.statusCode() != 200) {
                throw new IllegalStateException(
                        "Unexpected response code %d while downloading OSV advisory %s".formatted(
                                response.statusCode(), advisoryId));
            }

            try {
                return objectMapper.readValue(response.body(), Osv.class);
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to read OSV advisory " + advisoryId, e);
            }
        }

        @Override
        public void close() {
            // Nothing to do
        }

    }

}
