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

import alpine.common.util.ProxyConfig;
import alpine.common.util.ProxyUtil;
import alpine.config.AlpineConfigKeys;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import jakarta.annotation.Nullable;
import net.minidev.json.JSONObject;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;

/**
 * @since 1.8.0
 */
public class OidcConfigurationResolver {

    private static final OidcConfigurationResolver INSTANCE = new OidcConfigurationResolver(
            ConfigProvider.getConfig().getValue(AlpineConfigKeys.OIDC_ENABLED, Boolean.class),
            ConfigProvider.getConfig().getOptionalValue(AlpineConfigKeys.OIDC_ISSUER, String.class).orElse(null)
    );
    private static final Logger LOGGER = LoggerFactory.getLogger(OidcConfigurationResolver.class);

    private static volatile OidcConfiguration cachedConfiguration;

    private final boolean oidcEnabled;
    private final String issuer;

    OidcConfigurationResolver(final boolean oidcEnabled, final String issuer) {
        this.oidcEnabled = oidcEnabled;
        this.issuer = issuer;
    }

    public static OidcConfigurationResolver getInstance() {
        return INSTANCE;
    }

    /**
     * Resolve the {@link OidcConfiguration} either from a remote authorization server or from cache.
     *
     * @return The resolved {@link OidcConfiguration} or {@code null}, when resolving was not possible
     */
    @Nullable
    public OidcConfiguration resolve() {
        if (!oidcEnabled) {
            LOGGER.debug("Will not resolve OIDC configuration: OIDC is disabled");
            return null;
        }

        if (issuer == null) {
            LOGGER.error("Cannot resolve OIDC configuration: No issuer provided");
            return null;
        }

        OidcConfiguration configuration = cachedConfiguration;
        if (configuration != null) {
            LOGGER.debug("OIDC configuration loaded from cache");
            return configuration;
        }

        LOGGER.debug("Fetching OIDC configuration from issuer {}", issuer);
        try {
            Issuer issuerObject = new Issuer(this.issuer);
            URL configURL = OIDCProviderMetadata.resolveURL(issuerObject);
            HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, configURL);
            final ProxyConfig proxyCfg = ProxyUtil.getProxyConfig();

            if (proxyCfg != null && proxyCfg.shouldProxy(configURL)) {
                httpRequest.setProxy(proxyCfg.getProxy());
            }

            HTTPResponse httpResponse = httpRequest.send();

            if (httpResponse.getStatusCode() != 200) {
                throw new IOException("Couldn't download OpenID Provider metadata from " + configURL +
                        ": Status code " + httpResponse.getStatusCode());
            }

            JSONObject jsonObject = httpResponse.getContentAsJSONObject();

            OIDCProviderMetadata op = OIDCProviderMetadata.parse(jsonObject);

            if (!issuerObject.equals(op.getIssuer())) {
                throw new GeneralException("The returned issuer doesn't match the expected: " + op.getIssuer());
            }

            configuration = new OidcConfiguration();
            configuration.setIssuer(op.getIssuer().getValue());
            configuration.setJwksUri(op.getJWKSetURI());
            configuration.setUserInfoEndpointUri(op.getUserInfoEndpointURI());

            LOGGER.debug("Storing OIDC configuration in cache: {}", configuration);
            cachedConfiguration = configuration;

            return configuration;

        } catch (IOException | GeneralException e) {
            LOGGER.error("Failed to fetch OIDC configuration from issuer {}", issuer, e);
            return null;
        }
    }

    static void resetCache() {
        cachedConfiguration = null;
    }

    static void seedCache(OidcConfiguration configuration) {
        cachedConfiguration = configuration;
    }

}
