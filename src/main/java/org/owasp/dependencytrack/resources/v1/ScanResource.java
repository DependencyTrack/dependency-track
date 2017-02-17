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

import alpine.model.ApiKey;
import alpine.model.LdapUser;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.Principal;

@Path("/v1/scan")
@Api(value = "scan")
public class ScanResource extends AlpineResource {

    /*
    @PUT
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Upload Dependency-Check Result",
            notes = "Expects dependency-check-report.xml schema version 1.3 or higher"
    )
    public Response uploadScan(@FormDataParam("file") InputStream uploadedInputStream,
                               @FormDataParam("file") FormDataContentDisposition fileDetail) {

        if (fileDetail.getSize() > (100 * 1024) * 1024) { // 100 MB
            return Response.status(413).build();
        }

        File scanFile = new File("/Users/steve/Desktop/test.xml");
        try {
            FileUtils.copyInputStreamToFile(uploadedInputStream, scanFile);
            EventService.getInstance().publish(new ScanUploadEvent(scanFile));
            return Response.ok().build();
        } catch (IOException e) {
            return Response.serverError().build();
        }
    }
    */

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Upload Dependency-Check Result",
            notes = "Expects one or more dependency-check-report.xml schema version 1.3 or higher, and a valid project version UUID"
    )
    public Response uploadScan(ScanSubmitRequest request) {
        if (request.getProjectVersion() == null || request.getProjectVersion().getUuid() == null ||
                request.getScans() == null || request.getScans().length == 0) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        // Retrieve the optional principal that initiated this request
        Principal principal = getPrincipal();
        if (principal != null) {
            if (isLdapUser()) {
                LdapUser ldapUser = (LdapUser) principal;
            } else {
                ApiKey apiKey = (ApiKey) principal;
            }
        }

/*
        if (fileDetail.getSize() > (100 * 1024) * 1024) { // 100 MB
            return Response.status(413).build();
        }

        File scanFile = new File("/Users/steve/Desktop/test.xml");
        try {
            FileUtils.copyInputStreamToFile(uploadedInputStream, scanFile);
            EventService.getInstance().publish(new ScanUploadEvent(scanFile));
            return Response.ok().build();
        } catch (IOException e) {
            return Response.serverError().build();
        }
        */

        return null;
    }

}
