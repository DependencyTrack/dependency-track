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
package org.dependencytrack.notification.templating.pebble;

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.notification.api.templating.NotificationTemplateRenderer;
import org.dependencytrack.notification.api.templating.RenderedNotificationTemplate;
import org.dependencytrack.notification.proto.v1.Notification;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @see <a href="https://github.com/DependencyTrack/dependency-track/issues/6786">#6786</a>
 */
class PebbleNotificationTemplateRendererTest {

    @ParameterizedTest
    @MethodSource("baseUrlNormalizationArguments")
    void shouldNormalizeBaseUrlTrailingSlashes(String configuredBaseUrl, String expectedBaseUrl) {
        final RenderedNotificationTemplate rendered = render(
                configuredBaseUrl,
                """
                        Vulnerability URL: {{ baseUrl }}/vulnerability/?source=GITHUB&vulnId=GHSA-45gg-vh54-h5m9
                        Component URL:     {{ baseUrl }}/component/?uuid=a0f76ff1-4f7b-4c97-af53-a39629a4d18c
                        Project URL:       {{ baseUrl }}/projects/24593709-c6f4-4341-b8b4-852b8379a61e
                        Other affected projects: {{ baseUrl }}{{ frontendUri }}\
                        """,
                Map.of("frontendUri", "/vulnerabilities/GITHUB/GHSA-45gg-vh54-h5m9/affectedProjects"));

        assertThat(rendered.content()).isEqualTo("""
                Vulnerability URL: %s/vulnerability/?source=GITHUB&vulnId=GHSA-45gg-vh54-h5m9
                Component URL:     %s/component/?uuid=a0f76ff1-4f7b-4c97-af53-a39629a4d18c
                Project URL:       %s/projects/24593709-c6f4-4341-b8b4-852b8379a61e
                Other affected projects: %s/vulnerabilities/GITHUB/GHSA-45gg-vh54-h5m9/affectedProjects\
                """.formatted(expectedBaseUrl, expectedBaseUrl, expectedBaseUrl, expectedBaseUrl));
        assertThat(rendered.content()).doesNotContain("//vulnerability")
                .doesNotContain("//component")
                .doesNotContain("//projects")
                .doesNotContain("//vulnerabilities");
    }

    private static Stream<Arguments> baseUrlNormalizationArguments() {
        return Stream.of(
                arguments("https://example.com", "https://example.com"),
                arguments("https://example.com/", "https://example.com"),
                arguments("https://example.com///", "https://example.com"),
                arguments("https://example.com/dependency-track", "https://example.com/dependency-track"),
                arguments("https://example.com/dependency-track/", "https://example.com/dependency-track"));
    }

    @Test
    void shouldLeaveNullBaseUrlAsNull() {
        final RenderedNotificationTemplate rendered = render(
                null,
                "baseUrl=[{{ baseUrl }}]",
                Map.of());

        // Pebble renders null variables as empty strings.
        assertThat(rendered.content()).isEqualTo("baseUrl=[]");
    }

    @Test
    void shouldLeaveEmptyBaseUrlEmpty() {
        final RenderedNotificationTemplate rendered = render(
                "",
                "baseUrl=[{{ baseUrl }}]",
                Map.of());

        assertThat(rendered.content()).isEqualTo("baseUrl=[]");
    }

    private static RenderedNotificationTemplate render(
            String baseUrl,
            String templateContent,
            Map<String, Object> additionalContext) {
        final NotificationTemplateRenderer renderer =
                new PebbleNotificationTemplateRendererFactory(
                        Map.of(PebbleNotificationTemplateRendererFactory.BASE_URL, () -> baseUrl))
                        .createRenderer(new NotificationTemplate(templateContent, "text/plain"));

        final RenderedNotificationTemplate rendered = renderer.render(
                Notification.newBuilder()
                        .setTimestamp(Timestamps.fromMillis(0L))
                        .build(),
                additionalContext);

        assertThat(rendered).isNotNull();
        return rendered;
    }

}
