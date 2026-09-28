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

import alpine.model.ServiceAccount;
import alpine.server.auth.AuthenticationNotRequired;
import alpine.server.auth.SessionTokenService;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.tokenexchange.TokenExchangeGrant;
import org.dependencytrack.api.v2.OAuthApi;
import org.dependencytrack.api.v2.model.CreateOauthTokenResponse;
import org.dependencytrack.api.v2.model.ProblemDetails;
import org.dependencytrack.auth.OAuthErrorException;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityBindingDao;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityBindingDao.MatchingBindingRow;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityConditionEnv;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityKeySetFetcher;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityProvider;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityProviderDao;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityProviderDao.ExchangeProviderRow;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityTokenException;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityTokenVerifier;
import org.dependencytrack.common.HttpClient;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v2.exception.ProblemDetailsException;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/// @since 5.2.0
@Provider
@NullMarked
public final class OAuthResource extends AbstractApiResource implements OAuthApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthResource.class);
    private static final Set<TokenTypeURI> SUPPORTED_SUBJECT_TOKEN_TYPES =
            Set.of(TokenTypeURI.JWT, TokenTypeURI.ID_TOKEN);
    private static final WorkloadIdentityTokenVerifier TOKEN_VERIFIER =
            new WorkloadIdentityTokenVerifier(new WorkloadIdentityKeySetFetcher(HttpClient.INSTANCE));

    // Patterns required for manual validation. Keep in sync with OpenAPI spec.
    private static final Pattern PROVIDER_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$");
    private static final Pattern SERVICE_ACCOUNT_NAME_PATTERN =
            Pattern.compile("^(?![sS][vV][cC]:)[a-zA-Z0-9][a-zA-Z0-9+=,.:@_-]{0,58}$");

    @Override
    @AuthenticationNotRequired
    public Response createOAuthToken(
            @Nullable String grantType,
            @Nullable String subjectToken,
            @Nullable String subjectTokenType,
            @Nullable String requestedTokenType,
            @Nullable String workloadIdentityProvider,
            @Nullable String serviceAccount) {
        // NB: openapi-generator doesn't generate bean validation annotations for form fields,
        // so validation must be done manually.
        final TokenExchangeGrant grant = parseGrant(grantType, subjectToken, subjectTokenType, requestedTokenType);
        final String providerName =
                requireParameter("workload_identity_provider", workloadIdentityProvider, PROVIDER_NAME_PATTERN);
        final String serviceAccountName =
                requireParameter("service_account", serviceAccount, SERVICE_ACCOUNT_NAME_PATTERN);

        final CreatedSession session;
        try {
            session = exchange(grant, providerName, serviceAccountName);
        } catch (WorkloadIdentityTokenException e) {
            LOGGER.info(
                    SecurityMarkers.SECURITY_FAILURE,
                    "Exchange refused for provider {}: {}",
                    providerName,
                    e.getMessage());
            throw OAuthErrorException.refused();
        }

        return Response.ok(CreateOauthTokenResponse.builder()
                        .accessToken(session.token())
                        .issuedTokenType(TokenTypeURI.ACCESS_TOKEN.toString())
                        .tokenType(AccessTokenType.BEARER.getValue())
                        .expiresIn(session.lifetimeSeconds())
                        .build())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header("Pragma", "no-cache")
                .build();
    }

    private record CreatedSession(String token, int lifetimeSeconds) {}

    private static TokenExchangeGrant parseGrant(
            @Nullable String grantType,
            @Nullable String subjectToken,
            @Nullable String subjectTokenType,
            @Nullable String requestedTokenType) {
        final var params = new HashMap<String, List<String>>();
        if (grantType != null) {
            params.put("grant_type", List.of(grantType));
        }
        if (subjectToken != null) {
            params.put("subject_token", List.of(subjectToken));
        }
        if (subjectTokenType != null) {
            params.put("subject_token_type", List.of(subjectTokenType));
        }
        if (requestedTokenType != null) {
            params.put("requested_token_type", List.of(requestedTokenType));
        }

        final TokenExchangeGrant grant;
        try {
            grant = TokenExchangeGrant.parse(params);
        } catch (ParseException e) {
            throw new OAuthErrorException(e.getErrorObject());
        }

        if (!SUPPORTED_SUBJECT_TOKEN_TYPES.contains(grant.getSubjectTokenType())) {
            throw OAuthErrorException.invalidRequest("subject_token_type is not supported");
        }
        if (grant.getRequestedTokenType() != null && !TokenTypeURI.ACCESS_TOKEN.equals(grant.getRequestedTokenType())) {
            throw OAuthErrorException.invalidRequest("requested_token_type is not supported");
        }
        if (grant.getSubjectToken().getValue().length() > 16384 /* (16KiB) */) {
            throw OAuthErrorException.invalidRequest("subject_token is too large");
        }

        return grant;
    }

    private static String requireParameter(String name, @Nullable String value, Pattern pattern) {
        if (value == null || value.isBlank()) {
            throw OAuthErrorException.invalidRequest("%s is missing".formatted(name));
        }
        if (!pattern.matcher(value).matches()) {
            throw OAuthErrorException.invalidRequest("%s is invalid".formatted(name));
        }

        return value;
    }

    private CreatedSession exchange(TokenExchangeGrant grant, String providerName, String serviceAccountName) {
        final ExchangeProviderRow providerRow = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(WorkloadIdentityProviderDao.class).getExchangeProviderByName(providerName));
        if (providerRow == null) {
            throw new WorkloadIdentityTokenException("No provider with this name exists");
        }
        if (providerRow.provider().type() != WorkloadIdentityProvider.Type.OIDC
                && TokenTypeURI.ID_TOKEN.equals(grant.getSubjectTokenType())) {
            throw new WorkloadIdentityTokenException("ID tokens are only accepted by OIDC providers");
        }

        final JWTClaimsSet verifiedTokenClaims;
        try {
            verifiedTokenClaims = TOKEN_VERIFIER.verify(
                    providerRow.provider(), grant.getSubjectToken().getValue());
        } catch (KeySourceException e) {
            LOGGER.warn(
                    SecurityMarkers.SECURITY_FAILURE,
                    "Exchange failed for provider {}: keys cannot be fetched: {}",
                    providerName,
                    e.getMessage());
            throw new ProblemDetailsException(ProblemDetails.builder()
                    .status(Response.Status.SERVICE_UNAVAILABLE.getStatusCode())
                    .title("Service Unavailable")
                    .detail("The keys to verify the subject token cannot be fetched. Try again later.")
                    .build());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ServerErrorException(Response.Status.SERVICE_UNAVAILABLE, e);
        }

        return inJdbiTransaction(
                getAlpineRequest(),
                handle -> createSession(
                        handle,
                        providerName,
                        serviceAccountName,
                        providerRow.sessionLifetimeSeconds(),
                        verifiedTokenClaims));
    }

    private CreatedSession createSession(
            Handle handle,
            String providerName,
            String serviceAccount,
            int sessionLifetimeSeconds,
            JWTClaimsSet verifiedTokenClaims) {
        final String claimsJson = verifiedTokenClaims.toString();
        final Predicate<String> claimsMatcher =
                WorkloadIdentityConditionEnv.getInstance().matcher(claimsJson);

        final var bindingDao = handle.attach(WorkloadIdentityBindingDao.class);
        final MatchingBindingRow binding = bindingDao
                .findMatchingBindings(
                        providerName, ServiceAccount.usernameOf(serviceAccount), verifiedTokenClaims.getSubject())
                .stream()
                .filter(candidate -> candidate.condition() == null || claimsMatcher.test(candidate.condition()))
                .findFirst()
                .orElseThrow(() -> new WorkloadIdentityTokenException(
                        "No binding of service account %s matches subject %s, claims: %s"
                                .formatted(serviceAccount, verifiedTokenClaims.getSubject(), claimsJson)));
        if (binding.suspended()) {
            throw new WorkloadIdentityTokenException("Service account %s is suspended".formatted(binding.username()));
        }

        final String sessionToken = new SessionTokenService()
                .createSession(handle.getConnection(), binding.userId(), Duration.ofSeconds(sessionLifetimeSeconds));
        bindingDao.updateLastUsedAt(binding.id());

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                """
                Exchanged subject token of provider {} for a session of service account \
                {} via binding {}, subject {}, jti {}\
                """,
                providerName,
                binding.username(),
                binding.id(),
                verifiedTokenClaims.getSubject(),
                verifiedTokenClaims.getJWTID());
        return new CreatedSession(sessionToken, sessionLifetimeSeconds);
    }
}
