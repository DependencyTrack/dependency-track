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

import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FileSecretKeysHandlerFactoryTest {

    @Test
    void shouldReadSecretFromFile(@TempDir final Path tempDir) throws Exception {
        final Path secretFile = Files.writeString(tempDir.resolve("secret"), "s3cr3t\n");

        final SmallRyeConfig config = new SmallRyeConfigBuilder()
                .addDiscoveredSecretKeysHandlers()
                .addDefaultInterceptors()
                .withDefaultValues(Map.of("dt.password", "${file::" + secretFile + "}"))
                .build();

        assertThat(config.getValue("dt.password", String.class)).isEqualTo("s3cr3t");
    }

    @Test
    void shouldStripOnlyTrailingWhitespace(@TempDir final Path tempDir) throws Exception {
        final Path secretFile = Files.writeString(tempDir.resolve("secret"), "  pass word  \n\n");

        final SmallRyeConfig config = new SmallRyeConfigBuilder()
                .addDiscoveredSecretKeysHandlers()
                .addDefaultInterceptors()
                .withDefaultValues(Map.of("dt.password", "${file::" + secretFile + "}"))
                .build();

        assertThat(config.getValue("dt.password", String.class)).isEqualTo("  pass word");
    }

    @Test
    void shouldDecodeNonAsciiContentAsUtf8(@TempDir final Path tempDir) throws Exception {
        final String secret = "pässwörd-π-✓";
        final Path secretFile = tempDir.resolve("secret");
        Files.write(secretFile, secret.getBytes(StandardCharsets.UTF_8));

        final SmallRyeConfig config = new SmallRyeConfigBuilder()
                .addDiscoveredSecretKeysHandlers()
                .addDefaultInterceptors()
                .withDefaultValues(Map.of("dt.password", "${file::" + secretFile + "}"))
                .build();

        assertThat(config.getValue("dt.password", String.class)).isEqualTo(secret);
    }

    @Test
    void shouldThrowWhenFileExceedsMaxSize(@TempDir final Path tempDir) throws Exception {
        final byte[] oversize = new byte[FileSecretKeysHandlerFactory.MAX_BYTES + 1];
        final Path secretFile = tempDir.resolve("secret");
        Files.write(secretFile, oversize);

        final SmallRyeConfig config = new SmallRyeConfigBuilder()
                .addDiscoveredSecretKeysHandlers()
                .addDefaultInterceptors()
                .withDefaultValues(Map.of("dt.password", "${file::" + secretFile + "}"))
                .build();

        assertThatThrownBy(() -> config.getValue("dt.password", String.class))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("exceeds maximum size");
    }

    @Test
    void shouldReturnEmptyStringForEmptyFile(@TempDir final Path tempDir) throws Exception {
        final Path secretFile = Files.writeString(tempDir.resolve("secret"), "");

        final SmallRyeConfig config = new SmallRyeConfigBuilder()
                .addDiscoveredSecretKeysHandlers()
                .addDefaultInterceptors()
                .withDefaultValues(Map.of("dt.password", "${file::" + secretFile + "}"))
                .build();

        assertThat(config.getOptionalValue("dt.password", String.class)).isEmpty();
    }

    @Test
    void shouldThrowWhenFileDoesNotExist(@TempDir final Path tempDir) {
        final Path missing = tempDir.resolve("missing");

        final SmallRyeConfig config = new SmallRyeConfigBuilder()
                .addDiscoveredSecretKeysHandlers()
                .addDefaultInterceptors()
                .withDefaultValues(Map.of("dt.password", "${file::" + missing + "}"))
                .build();

        assertThatThrownBy(() -> config.getValue("dt.password", String.class))
                .isInstanceOf(IllegalStateException.class);
    }

}
