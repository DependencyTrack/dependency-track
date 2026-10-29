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
package org.dependencytrack.resources.v2;

import alpine.server.auth.AuthenticationNotRequired;
import alpine.server.auth.SessionTokenService;
import org.dependencytrack.api.v2.SamlApi;
import org.dependencytrack.api.v2.model.CreateSamlTokenResponse;
import org.dependencytrack.api.v2.model.GetSamlAvailabilityResponse;
import org.dependencytrack.api.v2.model.ProblemDetails;
import org.dependencytrack.auth.saml.SamlConfig;
import org.dependencytrack.auth.saml.SamlException;
import org.dependencytrack.auth.saml.SamlLoginService;
import org.dependencytrack.auth.saml.SamlLoginService.CompletedLogin;
import org.dependencytrack.auth.saml.SamlLoginService.FailureReason;
import org.dependencytrack.auth.saml.SamlLoginService.LoginRefusedException;
import org.dependencytrack.auth.saml.SamlLoginServiceHolder;
import org.dependencytrack.auth.saml.SamlMessages;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v2.exception.ProblemDetailsException;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/// @since 5.3.0
@Provider
@NullMarked
public final class SamlResource extends AbstractApiResource implements SamlApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlResource.class);

    private final SessionTokenService sessionTokenService = new SessionTokenService();

    @Override
    @AuthenticationNotRequired
    public Response getSamlAvailability() {
        return Response.ok(GetSamlAvailabilityResponse.builder()
                        .enabled(SamlLoginServiceHolder.get().isPresent())
                        .build())
                .build();
    }

    @Override
    @AuthenticationNotRequired
    public Response getSamlServiceProviderMetadata() {
        final SamlLoginService service = requireService();
        return Response.ok(SamlMessages.createServiceProviderMetadata(service.config()))
                .type("application/samlmetadata+xml")
                .build();
    }

    @Override
    @AuthenticationNotRequired
    public Response getSamlLogin(String codeChallenge, @Nullable String redirect) {
        final SamlLoginService service = requireService();
        if (!SamlLoginService.isValidCodeChallenge(codeChallenge)) {
            throw new BadRequestException("code_challenge is invalid");
        }

        final URI identityProviderUrl;
        try {
            identityProviderUrl = service.startLogin(codeChallenge, redirect);
        } catch (SamlException e) {
            LOGGER.error("Failed to start SAML login", e);
            throw new ProblemDetailsException(ProblemDetails.builder()
                    .status(Response.Status.SERVICE_UNAVAILABLE.getStatusCode())
                    .title("Service Unavailable")
                    .detail("The metadata of the identity provider cannot be loaded. Try again later.")
                    .build());
        }

        return Response.seeOther(identityProviderUrl)
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .build();
    }

    @Override
    @AuthenticationNotRequired
    public Response consumeSamlResponse(@Nullable String samlResponse, @Nullable String relayState) {
        final SamlLoginService service = requireService();
        final SamlConfig config = service.config();

        if (samlResponse == null || samlResponse.isBlank()) {
            LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "SAML login refused: response is missing");
            return redirectToFrontend(config, "error", FailureReason.FAILED.name(), null);
        }

        final CompletedLogin login;
        try {
            login = service.completeLogin(samlResponse);
        } catch (LoginRefusedException e) {
            LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "SAML login refused: {}", e.getMessage());
            return redirectToFrontend(config, "error", e.reason().name(), null);
        }

        LOGGER.info(SecurityMarkers.SECURITY_SUCCESS, "Successful SAML login / username: {}", login.username());
        return redirectToFrontend(config, "code", login.code(), login.redirectPath());
    }

    @Override
    @AuthenticationNotRequired
    public Response createSamlToken(@Nullable String code, @Nullable String codeVerifier) {
        requireService();
        if (code == null || code.isBlank() || code.length() > 64) {
            throw new BadRequestException("code is missing or invalid");
        }
        if (codeVerifier == null || !SamlLoginService.isValidCodeVerifier(codeVerifier)) {
            throw new BadRequestException("code_verifier is missing or invalid");
        }

        final Long userId = SamlLoginService.exchangeCode(code, codeVerifier, Instant.now());
        if (userId == null) {
            LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "SAML login code refused");
            throw new BadRequestException("The code is invalid, expired, or does not match the code verifier");
        }

        return Response.ok(CreateSamlTokenResponse.builder()
                        .token(sessionTokenService.createSession(userId))
                        .build())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .build();
    }

    private static SamlLoginService requireService() {
        return SamlLoginServiceHolder.get().orElseThrow(NotFoundException::new);
    }

    private static Response redirectToFrontend(
            SamlConfig config, String parameter, String value, @Nullable String redirectPath) {
        final String frontendUrl = config.frontendUrl().toString().replaceAll("/+$", "");
        final var location = new StringBuilder(frontendUrl)
                .append("/login/saml?")
                .append(parameter)
                .append('=')
                .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        if (redirectPath != null) {
            location.append("&redirect=").append(URLEncoder.encode(redirectPath, StandardCharsets.UTF_8));
        }

        return Response.seeOther(URI.create(location.toString()))
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .build();
    }
}
