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
package org.dependencytrack.support.config.secret.file;

import io.smallrye.config.ConfigSourceContext;
import io.smallrye.config.SecretKeysHandler;
import io.smallrye.config.SecretKeysHandlerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @since 5.0.0
 */
public final class FileSecretKeysHandlerFactory implements SecretKeysHandlerFactory {

    static final String NAME = "file";
    static final int MAX_BYTES = 64 * 1024;

    @Override
    public SecretKeysHandler getSecretKeysHandler(final ConfigSourceContext context) {
        return new FileSecretKeysHandler();
    }

    @Override
    public String getName() {
        return NAME;
    }

    private static final class FileSecretKeysHandler implements SecretKeysHandler {

        @Override
        public String decode(final String secretName) {
            final Path path = Path.of(secretName);
            try (final InputStream in = Files.newInputStream(path)) {
                final byte[] bytes = in.readNBytes(MAX_BYTES + 1);
                if (bytes.length > MAX_BYTES) {
                    throw new IllegalStateException(
                            "Secret file exceeds maximum size of %d bytes: %s".formatted(MAX_BYTES, path));
                }
                return new String(bytes, StandardCharsets.UTF_8).stripTrailing();
            } catch (IOException e) {
                throw new IllegalStateException("Failed to read secret from file: " + path, e);
            }
        }

        @Override
        public String getName() {
            return NAME;
        }

    }

}
