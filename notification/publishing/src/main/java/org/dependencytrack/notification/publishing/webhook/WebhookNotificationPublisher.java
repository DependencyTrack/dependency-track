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
package org.dependencytrack.notification.publishing.webhook;

import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.notification.api.templating.RenderedNotificationTemplate;
import org.dependencytrack.notification.proto.v1.Notification;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.publishing.http.HttpNotificationResponses.ensureSuccessful2xxResponse;

/**
 * @since 5.0.0
 */
final class WebhookNotificationPublisher implements NotificationPublisher {

    private static final String SIGNATURE_HEADER_NAME = "X-Webhook-Signature";

    private final HttpClient httpClient;

    WebhookNotificationPublisher(HttpClient httpClient) {
        this.httpClient = requireNonNull(httpClient, "httpClient must not be null");
    }

    @Override
    public void publish(NotificationPublishContext ctx, Notification notification) throws IOException {
        final var ruleConfig = ctx.ruleConfig(WebhookNotificationPublisherRuleConfigV1.class);

        final String mimeType;
        final byte[] bodyBytes;
        if (Boolean.TRUE.equals(ruleConfig.getPublishProtobuf())) {
            // https://protobuf.dev/reference/protobuf/mime-types/
            mimeType = "application/protobuf";
            bodyBytes = notification.toByteArray();
        } else {
            final RenderedNotificationTemplate renderedTemplate =
                    ctx.templateRenderer().render(notification);
            if (renderedTemplate == null) {
                throw new IllegalStateException("No template configured");
            }

            mimeType = renderedTemplate.mimeType();
            bodyBytes = renderedTemplate.content().getBytes(StandardCharsets.UTF_8);
        }

        final var requestBuilder = HttpRequest.newBuilder(ruleConfig.getDestinationUrl())
                .header("Content-Type", mimeType)
                .POST(BodyPublishers.ofByteArray(bodyBytes))
                .timeout(Duration.ofSeconds(10));

        final String signingSecret = ruleConfig.getSigningSecret();
        if (signingSecret != null) {
            requestBuilder.header(SIGNATURE_HEADER_NAME, calculateSignature(signingSecret, bodyBytes));
        }

        final String authHeaderName = ruleConfig.getAuthHeaderName();
        final String authHeaderValue = ruleConfig.getAuthHeaderValue();
        if (authHeaderName != null && authHeaderValue != null) {
            requestBuilder.header(authHeaderName, authHeaderValue);
        }

        try {
            final HttpResponse<InputStream> response =
                    httpClient.send(requestBuilder.build(), BodyHandlers.ofInputStream());
            ensureSuccessful2xxResponse(response);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RetryablePublishException("Interrupted while sending request", e);
        } catch (IOException e) {
            RetryablePublishException.throwIfRetryableNetworkError(e, "Request failed while sending notification");
            throw e;
        }
    }

    private static String calculateSignature(String secret, byte[] body) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return "sha256=" + HexFormat.of().formatHex(mac.doFinal(body));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Unable to calculate webhook signature", e);
        }
    }
}
