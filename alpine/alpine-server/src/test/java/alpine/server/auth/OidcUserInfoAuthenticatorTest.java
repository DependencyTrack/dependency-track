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
import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.RestoreEnvironmentVariables;
import org.junitpioneer.jupiter.SetEnvironmentVariable;
import wiremock.org.apache.hc.core5.http.ContentType;
import wiremock.org.apache.hc.core5.http.HttpHeaders;
import wiremock.org.apache.hc.core5.http.HttpStatus;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

@WireMockTest
public class OidcUserInfoAuthenticatorTest {

    private static final String USERNAME_CLAIM_NAME = "username";
    private static final String TEAMS_CLAIM_NAME = "groups";
    private static final OidcProfileCreator PROFILE_CREATOR = claims -> {
        final var profile = new OidcProfile();
        profile.setSubject(claims.getStringClaim(UserInfo.SUB_CLAIM_NAME));
        profile.setUsername(claims.getStringClaim(USERNAME_CLAIM_NAME));
        profile.setGroups(claims.getStringListClaim(TEAMS_CLAIM_NAME));
        profile.setEmail(claims.getStringClaim(UserInfo.EMAIL_CLAIM_NAME));
        return profile;
    };

    private OidcConfiguration oidcConfiguration;

    @BeforeEach
    public void setUp() {
        oidcConfiguration = new OidcConfiguration();
    }

    @Test
    public void authenticateShouldReturnOidcProfile(final WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Provide a UserInfo response with all required claims
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/userinfo"))
                .willReturn(WireMock.aResponse()
                        .withStatus(HttpStatus.SC_OK)
                        .withHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                        .withBody("" +
                                "{" +
                                "  \"" + UserInfo.SUB_CLAIM_NAME + "\": \"subject\", " +
                                "  \"" + USERNAME_CLAIM_NAME + "\": \"username\", " +
                                "  \"" + TEAMS_CLAIM_NAME + "\": [\"group1\",\"group2\"],\n" +
                                "  \"" + UserInfo.EMAIL_CLAIM_NAME + "\": \"username@example.com\"" +
                                "}")));

        oidcConfiguration.setUserInfoEndpointUri(new URI(wmRuntimeInfo.getHttpBaseUrl() + "/userinfo"));

        final var authenticator = new OidcUserInfoAuthenticator(oidcConfiguration);

        final OidcProfile profile = authenticator.authenticate("accessToken", PROFILE_CREATOR);
        assertThat(profile.getSubject()).isEqualTo("subject");
        assertThat(profile.getUsername()).isEqualTo("username");
        assertThat(profile.getGroups()).containsExactly("group1", "group2");
        assertThat(profile.getEmail()).isEqualTo("username@example.com");
    }

    @Test
    public void authenticateShouldThrowWhenUserInfoRequestFailed(final WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Simulate an error during the request
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/userinfo"))
                .willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));

        oidcConfiguration.setUserInfoEndpointUri(new URI(wmRuntimeInfo.getHttpBaseUrl() + "/userinfo"));

        final var authenticator = new OidcUserInfoAuthenticator(oidcConfiguration);

        Assertions.assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(() -> authenticator.authenticate("accessToken", PROFILE_CREATOR))
                .satisfies(exception -> assertThat(exception.getCauseType())
                        .isEqualTo(AlpineAuthenticationException.CauseType.OTHER));
    }

    @Test
    public void authenticateShouldThrowWhenParsingUserInfoResponseFailed(final WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Simulate a response with unparseable body
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/userinfo"))
                .willReturn(WireMock.aResponse()
                        .withStatus(HttpStatus.SC_OK)
                        .withHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_XML.getMimeType())
                        .withBody("<?xml version=\"1.0\"?>")));

        oidcConfiguration.setUserInfoEndpointUri(new URI(wmRuntimeInfo.getHttpBaseUrl() + "/userinfo"));

        final var authenticator = new OidcUserInfoAuthenticator(oidcConfiguration);

        Assertions.assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(() -> authenticator.authenticate("accessToken", PROFILE_CREATOR))
                .satisfies(exception -> assertThat(exception.getCauseType())
                        .isEqualTo(AlpineAuthenticationException.CauseType.OTHER));
    }

    @Test
    public void authenticateShouldThrowWhenUserInfoResponseIndicatesError(final WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Simulate a response indicating an invalid access token
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/userinfo"))
                .willReturn(WireMock.aResponse()
                        .withStatus(HttpStatus.SC_UNAUTHORIZED)
                        .withHeader("WWW-Authenticate", "Bearer error=invalid_token")));

        oidcConfiguration.setUserInfoEndpointUri(new URI(wmRuntimeInfo.getHttpBaseUrl() + "/userinfo"));

        final var authenticator = new OidcUserInfoAuthenticator(oidcConfiguration);

        Assertions.assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(() -> authenticator.authenticate("accessToken", PROFILE_CREATOR))
                .satisfies(exception -> assertThat(exception.getCauseType())
                        .isEqualTo(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS));
    }

    @Test
    @RestoreEnvironmentVariables
    @SetEnvironmentVariable(key = "http_proxy", value = "http://localhost:6666")
    public void authenticateShouldUseHttpProxyIfConfigured(final WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/userinfo"))
                .willReturn(WireMock.aResponse()
                        .withStatus(418)));

        oidcConfiguration.setUserInfoEndpointUri(new URI(wmRuntimeInfo.getHttpBaseUrl() + "/userinfo"));

        final var authenticator = new OidcUserInfoAuthenticator(oidcConfiguration);

        // Attempt to authenticate.
        // Should try to use the configured HTTP proxy, which will fail.
        Assertions.assertThatExceptionOfType(AlpineAuthenticationException.class)
                .isThrownBy(() -> authenticator.authenticate("accessToken", PROFILE_CREATOR));

        // No request should've reached its target.
        WireMock.verify(0, WireMock.getRequestedFor(WireMock.urlPathEqualTo("/userinfo")));
    }

}