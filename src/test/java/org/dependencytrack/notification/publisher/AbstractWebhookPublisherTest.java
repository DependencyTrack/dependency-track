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
package org.dependencytrack.notification.publisher;

import jakarta.json.JsonObjectBuilder;
import org.junit.jupiter.api.BeforeEach;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BASE_URL;

public abstract class AbstractWebhookPublisherTest<T extends AbstractWebhookPublisher> extends AbstractPublisherTest<T> {

    AbstractWebhookPublisherTest(final DefaultNotificationPublishers publisher, final T publisherInstance) {
        super(publisher, publisherInstance);
    }

    @BeforeEach
    final void initAbstractWebhookPublisherTest() {
        qm.createConfigProperty(
                GENERAL_BASE_URL.getGroupName(),
                GENERAL_BASE_URL.getPropertyName(),
                "https://example.com",
                GENERAL_BASE_URL.getPropertyType(),
                GENERAL_BASE_URL.getDescription()
        );

        stubFor(post(anyUrl())
                .willReturn(aResponse()
                        .withStatus(200)));
    }

    @Override
    JsonObjectBuilder extraConfig() {
        return super.extraConfig()
                .add(Publisher.CONFIG_DESTINATION, wmRuntimeInfo.getHttpBaseUrl());
    }

}
