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
package org.dependencytrack.auth.saml;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class SamlIdpMetadataProviderTest {

    @RegisterExtension
    private static final WireMockExtension wireMock =
            WireMockExtension.newInstance().options(options().dynamicPort()).build();

    private static HttpClient httpClient;

    @BeforeAll
    static void beforeAll() {
        httpClient = HttpClient.newHttpClient();
    }

    @AfterAll
    static void afterAll() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

    private SamlIdpMetadataProvider provider() {
        return new SamlIdpMetadataProvider(
                URI.create(wireMock.baseUrl() + "/metadata"), null, httpClient, Clock.systemUTC());
    }

    @Test
    void shouldLoadMetadataFromUrl() throws Exception {
        wireMock.stubFor(
                get(urlPathEqualTo("/metadata")).willReturn(aResponse().withBody(TestIdentityProvider.metadataXml())));

        final SamlIdpMetadata metadata = provider().get();

        assertThat(metadata.entityId()).isEqualTo(TestIdentityProvider.ENTITY_ID);
        assertThat(metadata.singleSignOnUrl()).isEqualTo(TestIdentityProvider.SSO_URL);
    }

    @Test
    void shouldRefuseMetadataThatExceedsMaximumSize() {
        wireMock.stubFor(get(urlPathEqualTo("/metadata"))
                .willReturn(aResponse().withBody(new byte[SamlIdpMetadataProvider.MAX_METADATA_BYTES + 1])));

        assertThatExceptionOfType(SamlException.class)
                .isThrownBy(() -> provider().get())
                .havingCause()
                .withMessageContaining("exceeds");
    }

    @Test
    void shouldRefuseUnexpectedResponseCode() {
        wireMock.stubFor(get(urlPathEqualTo("/metadata")).willReturn(aResponse().withStatus(404)));

        assertThatExceptionOfType(SamlException.class)
                .isThrownBy(() -> provider().get())
                .havingCause()
                .withMessageContaining("Unexpected response code 404");
    }
}
