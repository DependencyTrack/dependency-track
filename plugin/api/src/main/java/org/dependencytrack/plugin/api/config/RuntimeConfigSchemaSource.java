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
package org.dependencytrack.plugin.api.config;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.NoSuchElementException;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public sealed interface RuntimeConfigSchemaSource {

    String getSchema(Class<? extends RuntimeConfig> configClass);

    record Literal(String schema) implements RuntimeConfigSchemaSource {

        public Literal {
            requireNonNull(schema, "schema must not be null");
        }

        @Override
        public String getSchema(Class<? extends RuntimeConfig> configClass) {
            return schema;
        }

    }

    record Resource(String resourcePath) implements RuntimeConfigSchemaSource {

        public Resource {
            requireNonNull(resourcePath, "resourcePath must not be null");
        }

        @Override
        public String getSchema(Class<? extends RuntimeConfig> configClass) {
            // Load relative to config class's package so the same class loader sees the resource (reliable in tests and plugin setups)
            final InputStream inputStream = configClass.getResourceAsStream(resourcePath);
            if (inputStream == null) {
                throw new NoSuchElementException("No resource found at " + resourcePath);
            }

            try (inputStream) {
                final byte[] schemaBytes = inputStream.readAllBytes();
                return new String(schemaBytes, StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

    }

}
