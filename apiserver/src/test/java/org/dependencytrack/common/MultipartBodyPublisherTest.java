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

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.net.http.HttpRequest;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Flow;

import static org.assertj.core.api.Assertions.assertThat;

class MultipartBodyPublisherTest {

    @Test
    void shouldBuildWithMultipleParts() {
        final var publisher = new MultipartBodyPublisher("test-boundary");
        publisher.addFormField("field1", "value1");
        publisher.addFormField("field2", "value2");
        publisher.addFilePart("attachment", "data.bin",
                new ByteArrayInputStream("binary-data".getBytes(StandardCharsets.UTF_8)),
                "application/octet-stream");

        assertThat(publisher.contentType()).isEqualTo("multipart/form-data; boundary=test-boundary");
        assertThat(bodyToString(publisher.build())).isEqualTo("""
                --test-boundary\r
                Content-Disposition: form-data; name="field1"\r
                \r
                value1\r
                --test-boundary\r
                Content-Disposition: form-data; name="field2"\r
                \r
                value2\r
                --test-boundary\r
                Content-Disposition: form-data; filename="data.bin"; name="attachment"\r
                Content-Type: application/octet-stream\r
                \r
                binary-data\r
                --test-boundary--\r
                """);
    }

    @Test
    void shouldBuildEmptyBody() {
        final var publisher = new MultipartBodyPublisher("test-boundary");

        assertThat(bodyToString(publisher.build())).isEqualTo("--test-boundary--\r\n");
    }

    private static String bodyToString(HttpRequest.BodyPublisher bodyPublisher) {
        final var outputStream = new java.io.ByteArrayOutputStream();
        bodyPublisher.subscribe(new Flow.Subscriber<>() {
            @Override
            public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(ByteBuffer item) {
                while (item.hasRemaining()) {
                    outputStream.write(item.get());
                }
            }

            @Override
            public void onError(Throwable throwable) {
            }

            @Override
            public void onComplete() {
            }
        });
        return outputStream.toString(StandardCharsets.UTF_8);
    }

}