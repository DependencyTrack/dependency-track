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
package org.dependencytrack.auth.workloadidentity;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.jspecify.annotations.Nullable;

import java.net.MalformedURLException;
import java.net.URI;
import java.text.ParseException;
import java.time.Duration;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/// @since 5.2.0
public final class WorkloadIdentityTokenVerifier {

    private static final Set<JWSAlgorithm> ALLOWED_ALGORITHMS = Set.of(
            JWSAlgorithm.RS256,
            JWSAlgorithm.RS384,
            JWSAlgorithm.RS512,
            JWSAlgorithm.PS256,
            JWSAlgorithm.PS384,
            JWSAlgorithm.PS512,
            JWSAlgorithm.ES256,
            JWSAlgorithm.ES384,
            JWSAlgorithm.ES512);
    private static final JOSEObjectTypeVerifier<SecurityContext> TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(
            JOSEObjectType.JWT, JOSEObjectType.JOSE, new JOSEObjectType("at+jwt"), null);

    private static final Set<String> REQUIRED_CLAIMS = Set.of("exp", "sub");
    private static final Duration OUTAGE_TOLERANCE = Duration.ofHours(1);

    private final WorkloadIdentityKeySetFetcher keySetFetcher;
    private final Duration keySetTimeToLive;
    private final Duration minFetchInterval;
    private final Cache<WorkloadIdentityProvider, JWKSource<SecurityContext>> keySources;

    public WorkloadIdentityTokenVerifier(WorkloadIdentityKeySetFetcher keySetFetcher) {
        this(
                keySetFetcher,
                Duration.ofMillis(JWKSourceBuilder.DEFAULT_CACHE_TIME_TO_LIVE),
                Duration.ofMillis(JWKSourceBuilder.DEFAULT_RATE_LIMIT_MIN_INTERVAL));
    }

    WorkloadIdentityTokenVerifier(
            WorkloadIdentityKeySetFetcher keySetFetcher, Duration keySetTimeToLive, Duration minFetchInterval) {
        this.keySetFetcher = requireNonNull(keySetFetcher, "keySetFetcher must not be null");
        this.keySetTimeToLive = requireNonNull(keySetTimeToLive, "keySetTimeToLive must not be null");
        this.minFetchInterval = requireNonNull(minFetchInterval, "minFetchInterval must not be null");
        this.keySources = Caffeine.newBuilder()
                .expireAfterAccess(OUTAGE_TOLERANCE)
                .maximumSize(256)
                .build();
    }

    public JWTClaimsSet verify(WorkloadIdentityProvider provider, String subjectToken)
            throws InterruptedException, KeySourceException {
        final SignedJWT signedJwt;
        try {
            signedJwt = SignedJWT.parse(subjectToken);
        } catch (ParseException e) {
            throw new WorkloadIdentityTokenException("Subject token is not a signed JWT", e);
        }

        final var processor = new DefaultJWTProcessor<>();
        processor.setJWSTypeVerifier(TYPE_VERIFIER);
        processor.setJWSKeySelector(new SvidAwareKeySelector<>(keySources.get(provider, this::createKeySource)));
        processor.setJWTClaimsSetVerifier(ClaimsVerifier.of(provider));

        try {
            return processor.process(signedJwt, null);
        } catch (BadJOSEException | JOSEException e) {
            if (Thread.interrupted()) {
                throw new InterruptedException();
            }
            if (e instanceof KeySourceException kse) {
                throw kse;
            }

            throw new WorkloadIdentityTokenException("Subject token was rejected: %s".formatted(e.getMessage()), e);
        }
    }

    private JWKSource<SecurityContext> createKeySource(WorkloadIdentityProvider provider) {
        if (provider.jwksUrl() == null) {
            try {
                return new ImmutableJWKSet<>(JWKSet.parse(requireNonNull(provider.jwks())));
            } catch (ParseException e) {
                throw new IllegalStateException("Stored key set of provider cannot be parsed", e);
            }
        }

        try {
            return JWKSourceBuilder.create(URI.create(provider.jwksUrl()).toURL(), keySetFetcher)
                    .cache(keySetTimeToLive.toMillis(), JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT)
                    .rateLimited(minFetchInterval.toMillis())
                    .outageTolerant(OUTAGE_TOLERANCE.toMillis())
                    .refreshAheadCache(false)
                    .build();
        } catch (IllegalArgumentException | MalformedURLException e) {
            throw new IllegalStateException("Stored key set URL of provider is invalid", e);
        }
    }

    private static final class ClaimsVerifier extends DefaultJWTClaimsVerifier<SecurityContext> {

        private final @Nullable String subjectPrefix;

        private ClaimsVerifier(String audience, @Nullable JWTClaimsSet exactMatchClaims, @Nullable String trustDomain) {
            super(audience, exactMatchClaims, REQUIRED_CLAIMS);
            this.subjectPrefix = trustDomain != null ? SpiffeTrustDomain.idPrefix(trustDomain) : null;
        }

        private static ClaimsVerifier of(WorkloadIdentityProvider provider) {
            return switch (provider.type()) {
                case OIDC ->
                    new ClaimsVerifier(
                            provider.audience(),
                            new JWTClaimsSet.Builder().issuer(provider.issuer()).build(),
                            /* trustDomain */ null);
                // SPIFFE tokens may omit the issuer. Their trust domain is part of the subject instead.
                case SPIFFE -> new ClaimsVerifier(provider.audience(), /* exactMatchClaims */ null, provider.issuer());
            };
        }

        @Override
        public void verify(JWTClaimsSet claimsSet, @Nullable SecurityContext context) throws BadJWTException {
            super.verify(claimsSet, context);

            final String subject = claimsSet.getSubject();
            if (subject == null || claimsSet.getExpirationTime() == null) {
                throw new BadJWTException("JWT sub or exp claim is null");
            }
            if (subjectPrefix != null && !subject.startsWith(subjectPrefix)) {
                throw new BadJWTException("JWT subject is outside the trust domain");
            }
        }
    }

    private static final class SvidAwareKeySelector<C extends SecurityContext> extends JWSVerificationKeySelector<C> {

        private SvidAwareKeySelector(JWKSource<C> jwkSource) {
            super(ALLOWED_ALGORITHMS, jwkSource);
        }

        @Override
        protected @Nullable JWKMatcher createJWKMatcher(JWSHeader jwsHeader) {
            if (!isAllowed(jwsHeader.getAlgorithm())) {
                return null;
            }

            return new JWKMatcher.Builder()
                    .keyType(KeyType.forAlgorithm(jwsHeader.getAlgorithm()))
                    .keyID(jwsHeader.getKeyID())
                    .keyUses(KeyUse.SIGNATURE, new KeyUse("jwt-svid"), null)
                    .algorithms(jwsHeader.getAlgorithm(), null)
                    .build();
        }
    }
}
