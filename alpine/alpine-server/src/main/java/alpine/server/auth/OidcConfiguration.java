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

import java.net.URI;

/**
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID Connect specification: OpenID Provider Metadata</a>
 * @since 1.8.0
 */
public class OidcConfiguration {

    private String issuer;
    private URI userInfoEndpointUri;
    private URI jwksUri;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(final String issuer) {
        this.issuer = issuer;
    }

    public URI getUserInfoEndpointUri() {
        return userInfoEndpointUri;
    }

    public void setUserInfoEndpointUri(final URI userInfoEndpointUri) {
        this.userInfoEndpointUri = userInfoEndpointUri;
    }

    public URI getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(final URI jwksUri) {
        this.jwksUri = jwksUri;
    }

    @Override
    public String toString() {
        return "OidcConfiguration{" +
                "issuer='" + issuer + '\'' +
                ", userInfoEndpointUri=" + userInfoEndpointUri +
                ", jwksUri=" + jwksUri +
                '}';
    }

}
