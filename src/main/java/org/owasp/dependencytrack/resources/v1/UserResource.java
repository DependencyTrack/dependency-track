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
package org.owasp.dependencytrack.resources.v1;

import org.owasp.dependencytrack.auth.AuthenticationNotRequired;
import org.owasp.dependencytrack.auth.JsonWebToken;
import org.owasp.dependencytrack.auth.KeyManager;
import org.owasp.dependencytrack.auth.LdapAuthenticator;
import org.owasp.dependencytrack.model.LdapUser;
import org.owasp.dependencytrack.persistence.QueryManager;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/v1/user")
@Api(value = "user")
public class UserResource extends BaseResource {

    @POST
    @Path("login")
    @Produces(MediaType.TEXT_PLAIN)
    @ApiOperation(
            value = "Assert login credentials",
            notes = "Upon a successful login, a JSON Web Token will be returned in the response body. This functionality requires authentication to be enabled.",
            response = String.class
    )
    @AuthenticationNotRequired
    public Response validateCredentials(@FormParam("username") String username, @FormParam("password") String password) {

        LdapAuthenticator ldapAuth = new LdapAuthenticator();
        boolean isValid = ldapAuth.validateCredentials(username, password);
        if (!isValid) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        QueryManager qm = new QueryManager();
        LdapUser ldapUser = qm.getLdapUser(username);
        KeyManager km = KeyManager.getInstance();
        JsonWebToken jwt = new JsonWebToken(km.getSecretKey());
        String token = jwt.createToken(ldapUser);
        return Response.ok(token).build();
    }

}
