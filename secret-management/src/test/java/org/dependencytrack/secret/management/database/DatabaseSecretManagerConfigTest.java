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
package org.dependencytrack.secret.management.database;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class DatabaseSecretManagerConfigTest {

    @Test
    void shouldReturnNullWhenKekNotConfigured() {
        final var config = new DatabaseSecretManagerConfig(
                new SmallRyeConfigBuilder().build());

        assertThat(config.getKek()).isNull();
    }

    @Test
    void shouldReturnDecodedKekBytes() {
        final byte[] expectedBytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            expectedBytes[i] = (byte) i;
        }

        final var config = new DatabaseSecretManagerConfig(
                new SmallRyeConfigBuilder()
                        .withDefaultValues(Map.of(
                                "dt.secret-management.database.kek",
                                Base64.getEncoder().encodeToString(expectedBytes)))
                        .build());

        assertThat(config.getKek()).isEqualTo(expectedBytes);
    }

    @Test
    void shouldThrowWhenKekNotBase64() {
        final var config = new DatabaseSecretManagerConfig(
                new SmallRyeConfigBuilder()
                        .withDefaultValues(Map.of(
                                "dt.secret-management.database.kek", "invalid-base64"))
                        .build());

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(config::getKek)
                .withMessageContaining("not base64 encoded");
    }

    @Test
    void shouldThrowWhenKekWrongLength() {
        final byte[] shortKey = new byte[16];
        final var config = new DatabaseSecretManagerConfig(
                new SmallRyeConfigBuilder()
                        .withDefaultValues(Map.of(
                                "dt.secret-management.database.kek",
                                Base64.getEncoder().encodeToString(shortKey)))
                        .build());

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(config::getKek)
                .withMessageContaining("must be 32 bytes, but is 16");
    }

}
