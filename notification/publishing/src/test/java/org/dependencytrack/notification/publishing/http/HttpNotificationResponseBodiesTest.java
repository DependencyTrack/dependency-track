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

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class HttpNotificationResponseBodiesTest {

    @Test
    void readSnippetAndDiscardRemainderShouldReturnEmptyStringForNullBody() throws IOException {
        assertThat(HttpNotificationResponseBodies.readSnippetAndDiscardRemainder(null, 100)).isEmpty();
    }

    @Test
    void readSnippetAndDiscardRemainderShouldReturnEntireBodyWhenWithinLimit() throws IOException {
        final var body = new ByteArrayInputStream("short body".getBytes(StandardCharsets.UTF_8));

        assertThat(HttpNotificationResponseBodies.readSnippetAndDiscardRemainder(body, 100))
                .isEqualTo("short body");
        assertThat(body.read()).isEqualTo(-1);
    }

    @Test
    void readSnippetAndDiscardRemainderShouldLimitSnippetAndDrainRemainder() throws IOException {
        final var value = "a".repeat(10_000);
        final var body = new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));

        assertThat(HttpNotificationResponseBodies.readSnippetAndDiscardRemainder(body, 1000))
                .hasSize(1000)
                .isEqualTo("a".repeat(1000));
        assertThat(body.read()).isEqualTo(-1);
    }

}
