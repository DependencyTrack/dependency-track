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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.auth.PermissionRequired;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.integrations.FindingPackagingFormat;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.VulnerabilityUtil;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * JAX-RS resources for processing findings.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@Path("/v1/finding")
@Api(value = "finding", authorizations = @Authorization(value = "X-Api-Key"))
public class FindingResource extends AlpineResource {

    @GET
    @Path("/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all findings for a specific project",
            response = Finding.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of findings")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS)
    public Response getFindingsByProject(@PathParam("uuid") String uuid,
                                         @ApiParam(value = "Optionally includes suppressed findings")
                                         @QueryParam("suppressed") boolean suppressed,
                                         @ApiParam(value = "Optionally provide the minimum severity of findings to include")
                                         @QueryParam("minimumSeverity") String minimumSeverityFilter,
                                         @ApiParam(value = "Optionally provide a regex for purl of findings to include (filters are combined as AND)")
                                         @QueryParam("purl") String purlFilter,
                                         @ApiParam(value = "Optionally provide a regex for cpe of findings to include (filters are combined as AND)")
                                         @QueryParam("cpe") String cpeFilter) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final List<Finding> findings = qm.getFindings(project, suppressed);
                    List<Finding> filteredFindings = filter(findings, purlFilter, cpeFilter, minimumSeverityFilter);

                    return Response.ok(filteredFindings).header(TOTAL_COUNT_HEADER, filteredFindings.size()).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }
    private List<Finding> filter(List<Finding> findings,
                                 String purlFilter,
                                 String cpeFilter,
                                 String minimumSeverityFilter) {
        List<Finding> filteredPurlList =  findings;
        if (purlFilter != null && !purlFilter.isEmpty()) {
            filteredPurlList = findings.stream().filter(
                    finding -> finding.getComponent().getOrDefault("purl", "").toString().matches(purlFilter)
            ).collect(Collectors.toList());
        }

        // not working because CPE is not part of Finding.java
        List<Finding> filteredCpeList = findings;
        if (cpeFilter != null && !cpeFilter.isEmpty()) {
            filteredCpeList = findings.stream().filter(
                    finding -> finding.getComponent().getOrDefault("cpe", "").toString().matches(cpeFilter)
            ).collect(Collectors.toList());
        }

        List<Finding> minimumSeverityList = findings;
        if (minimumSeverityFilter != null && !minimumSeverityFilter.isEmpty()) {
            minimumSeverityList = findings.stream().filter(
                    finding -> VulnerabilityUtil.isMinimalSeverity(
                            VulnerabilityUtil.severityStringToSeverity(finding.getVulnerability().get("severity").toString()),
                            VulnerabilityUtil.severityStringToSeverity(minimumSeverityFilter))
            ).collect(Collectors.toList());
        }

        filteredPurlList.retainAll(minimumSeverityList);
        filteredPurlList.retainAll(filteredCpeList);
        return filteredPurlList;
    }

    @GET
    @Path("/project/{uuid}/export")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns the findings for the specified project as FPF"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS)
    public Response exportFindingsByProject(@PathParam("uuid") String uuid,
                                            @QueryParam("suppressed") boolean suppressed,
                                            @QueryParam("minimumSeverity") String minimumSeverityFilter,
                                            @QueryParam("purl") String purlFilter,
                                            @ApiParam(value = "Optionally provide a regex for cpe of findings to include")
                                            @QueryParam("cpe") String cpeFilter) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final List<Finding> findings = qm.getFindings(project);
                    List<Finding> filteredFindings = filter( findings, purlFilter, cpeFilter, minimumSeverityFilter);
                    final FindingPackagingFormat fpf = new FindingPackagingFormat(UUID.fromString(uuid), filteredFindings);
                    final Response.ResponseBuilder rb = Response.ok(fpf.getDocument().toString(), "application/json");
                    rb.header("Content-Disposition", "inline; filename=findings-" + uuid + ".fpf");
                    return rb.build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

}
