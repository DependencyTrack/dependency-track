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

import alpine.common.util.ProxyUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.time.Duration;

/**
 * @since 1.10.0
 */
class OidcIdTokenAuthenticator {

    private static final Logger LOGGER = LoggerFactory.getLogger(OidcIdTokenAuthenticator.class);
    private static final Duration JWK_SET_TTL = Duration.ofMinutes(5);

    private static volatile JWKSet cachedJwkSet;
    private static volatile long cachedJwkSetAtMillis;

    private final OidcConfiguration configuration;
    private final String clientId;

    OidcIdTokenAuthenticator(final OidcConfiguration configuration, final String clientId) {
        this.configuration = configuration;
        this.clientId = clientId;
    }

    OidcProfile authenticate(final String idToken, final OidcProfileCreator profileCreator) throws AlpineAuthenticationException {
        final SignedJWT parsedIdToken;
        try {
            parsedIdToken = SignedJWT.parse(idToken);
        } catch (ParseException e) {
            LOGGER.error("Parsing ID token failed", e);
            throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS);
        }

        final IDTokenClaimsSet claimsSet = validate(parsedIdToken, /* allowJwkRefresh */ true);
        LOGGER.debug("ID token claims: {}", claimsSet.toJSONString());
        return profileCreator.create(claimsSet);
    }

    private IDTokenClaimsSet validate(final SignedJWT parsedIdToken, final boolean allowJwkRefresh) throws AlpineAuthenticationException {
        final JWKSet jwkSet;
        try {
            jwkSet = resolveJwkSet(/* forceRefresh */ false);
        } catch (IOException | ParseException e) {
            LOGGER.error("Resolving JWK set failed", e);
            throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.OTHER);
        }

        final var idTokenValidator = new IDTokenValidator(
                new Issuer(configuration.getIssuer()), new ClientID(clientId),
                parsedIdToken.getHeader().getAlgorithm(), jwkSet);

        try {
            return idTokenValidator.validate(parsedIdToken, null);
        } catch (BadJOSEException e) {
            // Likely an unknown `kid` due to key rotation. Refresh the JWK set
            // once and retry. Surface real validation failures on the second pass.
            if (allowJwkRefresh) {
                LOGGER.debug("ID token validation failed against cached JWK set; refreshing and retrying", e);
                try {
                    resolveJwkSet(/* forceRefresh */ true);
                } catch (IOException | ParseException refreshFailure) {
                    LOGGER.error("Refreshing JWK set failed", refreshFailure);
                    throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.OTHER);
                }
                return validate(parsedIdToken, /* allowJwkRefresh */ false);
            }
            LOGGER.error("ID token validation failed", e);
            throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS);
        } catch (JOSEException e) {
            LOGGER.error("ID token validation failed", e);
            throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS);
        }
    }

    JWKSet resolveJwkSet() throws IOException, ParseException {
        return resolveJwkSet(false);
    }

    private JWKSet resolveJwkSet(boolean forceRefresh) throws IOException, ParseException {
        if (!forceRefresh) {
            final JWKSet existing = cachedJwkSet;
            final long ageMillis = System.currentTimeMillis() - cachedJwkSetAtMillis;
            if (existing != null && ageMillis < JWK_SET_TTL.toMillis()) {
                LOGGER.debug("JWK set loaded from cache");
                return existing;
            }
        }

        LOGGER.debug("Fetching JWK set from {}", configuration.getJwksUri());
        final URL jwksUrl = configuration.getJwksUri().toURL();

        final JWKSet fetched;
        final var proxyCfg = ProxyUtil.getProxyConfig();
        if (proxyCfg != null && proxyCfg.shouldProxy(jwksUrl)) {
            LOGGER.debug("Using proxy to fetch JWK set");
            fetched = JWKSet.load(jwksUrl, 0, 0, 0, proxyCfg.getProxy());
        } else {
            fetched = JWKSet.load(jwksUrl);
        }

        LOGGER.debug("Storing JWK set in cache");
        cachedJwkSet = fetched;
        cachedJwkSetAtMillis = System.currentTimeMillis();
        return fetched;
    }

    static void resetCache() {
        cachedJwkSet = null;
        cachedJwkSetAtMillis = 0L;
    }

    static void seedCache(final JWKSet jwkSet) {
        cachedJwkSet = jwkSet;
        cachedJwkSetAtMillis = System.currentTimeMillis();
    }

}
