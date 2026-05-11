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
package org.dependencytrack.common;

import org.glassfish.jersey.media.multipart.FormDataContentDisposition;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * @since 5.0.0
 */
public final class MultipartBodyPublisher {

    private final String boundary;
    private final List<Part> parts = new ArrayList<>();

    public MultipartBodyPublisher() {
        this(UUID.randomUUID().toString());
    }

    MultipartBodyPublisher(String boundary) {
        this.boundary = boundary;
    }

    public String contentType() {
        return "multipart/form-data; boundary=" + boundary;
    }

    public MultipartBodyPublisher addFormField(String name, String value) {
        parts.add(new FormField(name, value));
        return this;
    }

    public MultipartBodyPublisher addFilePart(
            String name,
            String filename,
            InputStream inputStream,
            String contentType) {
        parts.add(new FilePart(name, filename, inputStream, contentType));
        return this;
    }

    public HttpRequest.BodyPublisher build() {
        try {
            final var outputStream = new ByteArrayOutputStream();
            for (final Part part : parts) {
                outputStream.write(("--%s\r\n".formatted(boundary)).getBytes(StandardCharsets.UTF_8));
                part.writeTo(outputStream);
            }
            outputStream.write(("--%s--\r\n".formatted(boundary)).getBytes(StandardCharsets.UTF_8));
            return HttpRequest.BodyPublishers.ofByteArray(outputStream.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException("Failed to build multipart body", e);
        }
    }

    private sealed interface Part {
        void writeTo(ByteArrayOutputStream outputStream) throws IOException;
    }

    private record FormField(String name, String value) implements Part {

        @Override
        public void writeTo(ByteArrayOutputStream outputStream) throws IOException {
            final String contentDisposition = FormDataContentDisposition.name(name).build().toString();
            outputStream.write(
                    ("Content-Disposition: %s\r\n\r\n%s\r\n".formatted(
                            contentDisposition, value)).getBytes(StandardCharsets.UTF_8));
        }

    }

    private record FilePart(String name, String filename, InputStream inputStream, String contentType) implements Part {

        @Override
        public void writeTo(ByteArrayOutputStream outputStream) throws IOException {
            final var contentDisposition =
                    FormDataContentDisposition
                            .name(name)
                            .fileName(filename)
                            .build();
            outputStream.write(
                    ("Content-Disposition: %s\r\nContent-Type: %s\r\n\r\n".formatted(
                            contentDisposition, contentType)).getBytes(StandardCharsets.UTF_8));
            inputStream.transferTo(outputStream);
            outputStream.write("\r\n".getBytes(StandardCharsets.UTF_8));
        }

    }

}
