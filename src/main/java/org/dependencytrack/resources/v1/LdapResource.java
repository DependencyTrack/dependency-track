/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.auth.LdapConnectionWrapper;
import alpine.auth.PermissionRequired;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.dependencytrack.auth.Permissions;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;

/**
 * JAX-RS resources for processing LDAP group mapping requests.
 *
 * @author Steve Springett
 * @since 3.3.0
 */
@Path("/v1/ldap")
@Api(value = "ldap", authorizations = @Authorization(value = "X-Api-Key"))
public class LdapResource extends AlpineResource {


    @GET
    @Path("/groups")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns the DNs of all accessible groups within the directory",
            response = String.class,
            responseContainer = "List",
            notes = "This API performs a pass-thru query to the configured LDAP server. Group information is retrieved over the wire from the LDAP server."
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response retrieveLdapGroups () {
        final LdapConnectionWrapper ldap = new LdapConnectionWrapper();
        DirContext dirContext = null;
        try {
            dirContext = ldap.createDirContext();
            List<String> groups = ldap.getGroups(dirContext);
            return Response.ok(groups).build();
        } catch (NamingException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        } finally {
            ldap.closeQuietly(dirContext);
        }
    }
}
