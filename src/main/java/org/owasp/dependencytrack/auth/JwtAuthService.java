/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.auth;

import org.owasp.dependencytrack.persistence.QueryManager;
import org.glassfish.jersey.server.ContainerRequest;
import javax.naming.AuthenticationException;
import javax.ws.rs.core.HttpHeaders;
import java.security.Principal;
import java.util.List;

public class JwtAuthService implements AuthService {

    private String bearer = null;

    public JwtAuthService(ContainerRequest request) {
        this.bearer = getAuthorizationToken(request);
    }

    public boolean isSpecified() {
        return (bearer != null);
    }

    public Principal authenticate() throws AuthenticationException {
        KeyManager keyManager = KeyManager.getInstance();
        if (bearer != null) {
            JsonWebToken jwt = new JsonWebToken(keyManager.getSecretKey());
            boolean isValid = jwt.validateToken(bearer);
            if (isValid) {
                try (QueryManager queryManager = new QueryManager()) {
                    if (jwt.getSubject() == null || jwt.getExpiration() == null) return null;
                    return queryManager.getLdapUser(jwt.getSubject().toString());
                }
            }
        }
        return null;
    }

    private String getAuthorizationToken(HttpHeaders headers) {
        List<String> header = headers.getRequestHeader("Authorization");
        if (header != null) {
            String bearer = header.get(0);
            if (bearer != null) {
                return bearer.substring("Bearer ".length());
            }
        }
        return null;
    }

}