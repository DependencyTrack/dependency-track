/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */

package alpine.server.auth;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.RestoreEnvironmentVariables;
import org.junitpioneer.jupiter.SetEnvironmentVariable;
import wiremock.org.apache.hc.core5.http.ContentType;
import wiremock.org.apache.hc.core5.http.HttpHeaders;
import wiremock.org.apache.hc.core5.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

@WireMockTest
public class OidcConfigurationResolverTest {

    private static final String OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration";

    @AfterEach
    public void tearDown() {
        OidcConfigurationResolver.resetCache();
    }

    @Test
    public void resolveShouldReturnNullWhenOidcIsNotEnabled(final WireMockRuntimeInfo wmRuntimeInfo) {
        assertThat(new OidcConfigurationResolver(false, wmRuntimeInfo.getHttpBaseUrl()).resolve()).isNull();
    }

    @Test
    public void resolveShouldReturnNullWhenAuthorityIsNull() {
        assertThat(new OidcConfigurationResolver(true, null).resolve()).isNull();
    }

    @Test
    public void resolveShouldReturnCachedValueWhenAvailable(final WireMockRuntimeInfo wmRuntimeInfo) {
        final OidcConfiguration cachedConfiguration = new OidcConfiguration();
        OidcConfigurationResolver.seedCache(cachedConfiguration);

        assertThat(new OidcConfigurationResolver(true, wmRuntimeInfo.getHttpBaseUrl()).resolve()).isEqualTo(cachedConfiguration);
    }

    @Test
    public void resolveShouldReturnNullWhenServerRespondsWithNon200StatusCode(final WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(OPENID_CONFIGURATION_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(HttpStatus.SC_NOT_FOUND)));

        assertThat(new OidcConfigurationResolver(true, wmRuntimeInfo.getHttpBaseUrl()).resolve()).isNull();
        WireMock.verify(WireMock.getRequestedFor(WireMock.urlPathEqualTo(OPENID_CONFIGURATION_PATH)));
    }

    @Test
    public void resolveShouldReturnNullWhenServerRespondsWithInvalidJson(final WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(OPENID_CONFIGURATION_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(HttpStatus.SC_OK)
                        .withHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                        .withBody("<?xml version=\"1.0\" ?>")));

        assertThat(new OidcConfigurationResolver(true, wmRuntimeInfo.getHttpBaseUrl()).resolve()).isNull();
        WireMock.verify(WireMock.getRequestedFor(WireMock.urlPathEqualTo(OPENID_CONFIGURATION_PATH)));
    }

    @Test
    public void resolveShouldReturnConfigurationAndStoreItInCache(final WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(OPENID_CONFIGURATION_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(HttpStatus.SC_OK)
                        .withHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                        .withBody("" +
                                "{\n" +
                                "  \"issuer\": \"" + wmRuntimeInfo.getHttpBaseUrl() + "\",\n" +
                                "  \"userinfo_endpoint\": \"" + wmRuntimeInfo.getHttpBaseUrl() + "/protocol/openid-connect/userinfo\",\n" +
                                "  \"jwks_uri\": \"" + wmRuntimeInfo.getHttpBaseUrl() + "/protocol/openid-connect/certs\",\n" +
                                "  \"subject_types_supported\": [\"public\",\"pairwise\"]" +
                                "}")));

        final OidcConfiguration oidcConfiguration = new OidcConfigurationResolver(true, wmRuntimeInfo.getHttpBaseUrl()).resolve();
        assertThat(oidcConfiguration).isNotNull();
        assertThat(oidcConfiguration.getIssuer()).isEqualTo(wmRuntimeInfo.getHttpBaseUrl());
        assertThat(oidcConfiguration.getUserInfoEndpointUri().toString()).isEqualTo(wmRuntimeInfo.getHttpBaseUrl() + "/protocol/openid-connect/userinfo");
        assertThat(oidcConfiguration.getJwksUri().toString()).isEqualTo(wmRuntimeInfo.getHttpBaseUrl() + "/protocol/openid-connect/certs");

        // On the next invocation, the configuration should be loaded from cache
        assertThat(new OidcConfigurationResolver(true, wmRuntimeInfo.getHttpBaseUrl()).resolve()).isEqualTo(oidcConfiguration);

        // Only one request should've been made
        WireMock.verify(1, WireMock.getRequestedFor(WireMock.urlPathEqualTo(OPENID_CONFIGURATION_PATH)));
    }

    @Test
    @RestoreEnvironmentVariables
    @SetEnvironmentVariable(key = "http_proxy", value = "http://localhost:6666")
    public void resolveShouldUseHttpProxyIfConfigured(final WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(OPENID_CONFIGURATION_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(418)));

        // Attempt to resolve.
        // Should try to use the configured HTTP proxy, which will fail.
        assertThat(new OidcConfigurationResolver(true, wmRuntimeInfo.getHttpBaseUrl()).resolve()).isNull();

        // No request should've reached its target.
        WireMock.verify(0, WireMock.getRequestedFor(WireMock.urlPathEqualTo(OPENID_CONFIGURATION_PATH)));
    }

}