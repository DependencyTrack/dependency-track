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
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * @since 1.10.0
 */
class OidcUserInfoAuthenticator {

    private static final Logger LOGGER = LoggerFactory.getLogger(OidcUserInfoAuthenticator.class);

    private final OidcConfiguration configuration;

    OidcUserInfoAuthenticator(final OidcConfiguration configuration) {
        this.configuration = configuration;
    }

    OidcProfile authenticate(final String accessToken, final OidcProfileCreator profileCreator) throws AlpineAuthenticationException {
        final UserInfoResponse userInfoResponse;
        try {
            HTTPRequest httpRequest = new UserInfoRequest(configuration.getUserInfoEndpointUri(), new BearerAccessToken(accessToken)).toHTTPRequest();
            final ProxyConfig proxyCfg = ProxyUtil.getProxyConfig();

            if (proxyCfg != null && proxyCfg.shouldProxy(configuration.getUserInfoEndpointUri().toURL())) {
                httpRequest.setProxy(proxyCfg.getProxy());
            }
            final var httpResponse = httpRequest.send();
            userInfoResponse = UserInfoResponse.parse(httpResponse);
        } catch (IOException e) {
            LOGGER.error("UserInfo request failed", e);
            throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.OTHER);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOGGER.error("Parsing UserInfo response failed", e);
            throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.OTHER);
        }

        if (!userInfoResponse.indicatesSuccess()) {
            final var error = userInfoResponse.toErrorResponse().getErrorObject();
            LOGGER.error("UserInfo request failed (Code:{}, Description: {})", error.getCode(), error.getDescription());
            throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS);
        }

        final var userInfo = userInfoResponse.toSuccessResponse().getUserInfo();
        LOGGER.debug("UserInfo response: {}", userInfo.toJSONString());

        return profileCreator.create(userInfo);
    }

}
