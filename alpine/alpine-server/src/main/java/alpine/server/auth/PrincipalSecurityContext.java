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
package alpine.server.auth;

import alpine.model.auth.ApiKeyPrincipal;
import alpine.model.auth.Principal;
import alpine.model.auth.UserPrincipal;
import org.jspecify.annotations.NullMarked;

import jakarta.ws.rs.core.SecurityContext;

/// @since 5.2.0
@NullMarked
public record PrincipalSecurityContext(Principal principal, boolean secure, boolean portfolioAccessControlEnabled)
        implements SecurityContext {

    public static final String API_KEY_AUTH = "API_KEY";
    public static final String BEARER_AUTH = "BEARER";

    @Override
    public Principal getUserPrincipal() {
        return principal;
    }

    /// @throws UnsupportedOperationException Always.
    @Override
    public boolean isUserInRole(String role) {
        throw new UnsupportedOperationException("""
            Dependency-Track authorizes on permissions, not roles. \
            Use Principal#hasPermission(String) instead.\
            """);
    }

    @Override
    public boolean isSecure() {
        return secure;
    }

    @Override
    public String getAuthenticationScheme() {
        return switch (principal) {
            case ApiKeyPrincipal _ -> API_KEY_AUTH;
            case UserPrincipal _ -> BEARER_AUTH;
        };
    }
}
