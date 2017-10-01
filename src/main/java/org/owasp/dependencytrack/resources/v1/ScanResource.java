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

import alpine.auth.PermissionRequired;
import alpine.event.framework.EventService;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.owasp.dependencytrack.auth.Permission;
import org.owasp.dependencytrack.event.ScanUploadEvent;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.persistence.QueryManager;
import org.owasp.dependencytrack.resources.v1.vo.ScanSubmitRequest;
import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Base64;

/**
 * JAX-RS resources for processing scans.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/scan")
@Api(value = "scan", authorizations = @Authorization(value = "X-Api-Key"))
public class ScanResource extends AlpineResource {

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Upload Dependency-Check Result",
            notes = "Expects one or more dependency-check-report.xml schema version 1.3 or higher, and a valid project UUID"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permission.SCAN_UPLOAD)
    public Response uploadScan(ScanSubmitRequest request) {
        final Validator validator = getValidator();
        failOnValidationError(
                validator.validateProperty(request, "project"),
                validator.validateProperty(request, "scan")
        );
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, request.getProject());
            if (project != null) {
                final byte[] decodedScan = Base64.getDecoder().decode(request.getScan());
                EventService.getInstance().publish(new ScanUploadEvent(project.getUuid(), decodedScan));
                return Response.ok().build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

}
