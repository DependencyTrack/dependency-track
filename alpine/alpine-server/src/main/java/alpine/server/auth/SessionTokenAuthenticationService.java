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

import alpine.model.ManagedUser;
import alpine.model.UserSession;
import alpine.persistence.AlpineQueryManager;
import jakarta.ws.rs.core.HttpHeaders;
import org.glassfish.jersey.server.ContainerRequest;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import java.security.Principal;
import java.util.List;

/**
 * @since 5.0.0
 */
@NullMarked
public final class SessionTokenAuthenticationService implements AuthenticationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SessionTokenAuthenticationService.class);

    private final @Nullable String bearer;
    private @Nullable String tokenHash;

    public SessionTokenAuthenticationService(ContainerRequest request) {
        this.bearer = getAuthorizationToken(request);
    }

    @Override
    public boolean isSpecified() {
        return bearer != null;
    }

    @Override
    public @Nullable Principal authenticate() throws AuthenticationException {
        if (bearer == null) {
            return null;
        }

        final String hashedToken = SessionTokenService.sha256Hex(bearer);

        try (final var qm = new AlpineQueryManager()) {
            final UserSession session = qm.getUserSessionByTokenHash(hashedToken);
            if (session == null) {
                return null;
            }

            if (session.getUser() instanceof final ManagedUser user && user.isSuspended()) {
                LOGGER.debug("Successfully authenticated user {}, but the account is suspended", user.getUsername());
                return null;
            }

            this.tokenHash = hashedToken;

            return qm.detach(session.getUser());
        }
    }

    public @Nullable String getTokenHash() {
        return tokenHash;
    }

    private static @Nullable String getAuthorizationToken(HttpHeaders headers) {
        final List<String> header = headers.getRequestHeader("Authorization");
        if (header != null && !header.isEmpty()) {
            final String bearer = header.getFirst();
            if (bearer != null && bearer.regionMatches(true, 0, "Bearer ", 0, 7)) {
                return bearer.substring(7);
            }
        }

        return null;
    }

}
