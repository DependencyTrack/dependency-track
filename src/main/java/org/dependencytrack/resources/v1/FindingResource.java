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
package org.dependencytrack.resources.v1;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.model.About;
import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.core.Response.Status;
import org.apache.commons.lang3.text.WordUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.PolicyEvaluationEvent;
import org.dependencytrack.event.RepositoryMetaEvent;
import org.dependencytrack.event.VulnerabilityAnalysisEvent;
import org.dependencytrack.integrations.FindingPackagingFormat;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.GroupedFinding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
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

    private static final Logger LOGGER = Logger.getLogger(FindingResource.class);
    public static final String MEDIA_TYPE_SARIF_JSON = "application/sarif+json";

    @GET
    @Path("/project/{uuid}")
    @Produces({MediaType.APPLICATION_JSON, MEDIA_TYPE_SARIF_JSON})
    @ApiOperation(
            value = "Returns a list of all findings for a specific project or generates SARIF file if Accept: application/sarif+json header is provided",
            response = Finding.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of findings"),
            notes = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getFindingsByProject(@ApiParam(value = "The UUID of the project", format = "uuid", required = true)
                                         @PathParam("uuid") @ValidUuid String uuid,
                                         @ApiParam(value = "Optionally includes suppressed findings")
                                         @QueryParam("suppressed") boolean suppressed,
                                         @ApiParam(value = "Optionally limit findings to specific sources of vulnerability intelligence")
                                         @QueryParam("source") Vulnerability.Source source,
                                         @HeaderParam("accept") String acceptHeader) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    //final long totalCount = qm.getVulnerabilityCount(project, suppressed);
                    final List<Finding> findings = qm.getFindings(project, suppressed);
                    if (acceptHeader != null && acceptHeader.contains(MEDIA_TYPE_SARIF_JSON)) {
                        try {
                            return Response.ok(generateSARIF(findings), MEDIA_TYPE_SARIF_JSON)
                                .header("content-disposition","attachment; filename=\"findings-" + uuid + ".sarif\"")
                                .build();
                        } catch (IOException ioException) {
                            LOGGER.error(ioException.getMessage(), ioException);
                            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("An error occurred while generating SARIF file").build();
                        }
                    }
                    if (source != null) {
                        final List<Finding> filteredList = findings.stream().filter(finding -> source.name().equals(finding.getVulnerability().get("source"))).collect(Collectors.toList());
                        return Response.ok(filteredList).header(TOTAL_COUNT_HEADER, filteredList.size()).build();
                    } else {
                        return Response.ok(findings).header(TOTAL_COUNT_HEADER, findings.size()).build();
                    }
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/project/{uuid}/export")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns the findings for the specified project as FPF",
            notes = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response exportFindingsByProject(@ApiParam(value = "The UUID of the project", format = "uuid", required = true)
                                            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final List<Finding> findings = qm.getFindings(project);
                    final FindingPackagingFormat fpf = new FindingPackagingFormat(UUID.fromString(uuid), findings);
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

    @POST
    @Path("/project/{uuid}/analyze")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Triggers Vulnerability Analysis on a specific project",
            response = Project.class,
            notes = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response analyzeProject(
            @ApiParam(value = "The UUID of the project to analyze", format = "uuid", required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                  LOGGER.info("Analysis of project " + project.getUuid() + " requested by " + super.getPrincipal().getName());

                  final List<Component> detachedComponents = qm.detach(qm.getAllComponents(project));
                  final Project detachedProject = qm.detach(Project.class, project.getId());
                  final VulnerabilityAnalysisEvent vae = new VulnerabilityAnalysisEvent(detachedComponents).project(detachedProject);
                  // Wait for RepositoryMetaEvent after VulnerabilityAnalysisEvent,
                  // as both might be needed in policy evaluation
                  vae.onSuccess(new RepositoryMetaEvent(detachedComponents));
                  vae.onSuccess(new PolicyEvaluationEvent(detachedComponents).project(detachedProject));
                  Event.dispatch(vae);

                  return Response.ok(Collections.singletonMap("token", vae.getChainIdentifier())).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all findings",
            response = Finding.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of findings"),
            notes = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getAllFindings(@ApiParam(value = "Show inactive projects")
                                   @QueryParam("showInactive") boolean showInactive,
                                   @ApiParam(value = "Show suppressed findings")
                                   @QueryParam("showSuppressed") boolean showSuppressed,
                                   @ApiParam(value = "Filter by severity")
                                   @QueryParam("severity") String severity,
                                   @ApiParam(value = "Filter by analysis status")
                                   @QueryParam("analysisStatus") String analysisStatus,
                                   @ApiParam(value = "Filter by vendor response")
                                   @QueryParam("vendorResponse") String vendorResponse,
                                   @ApiParam(value = "Filter published from this date")
                                   @QueryParam("publishDateFrom") String publishDateFrom,
                                   @ApiParam(value = "Filter published to this date")
                                   @QueryParam("publishDateTo") String publishDateTo,
                                   @ApiParam(value = "Filter attributed on from this date")
                                   @QueryParam("attributedOnDateFrom") String attributedOnDateFrom,
                                   @ApiParam(value = "Filter attributed on to this date")
                                   @QueryParam("attributedOnDateTo") String attributedOnDateTo,
                                   @ApiParam(value = "Filter the text input in these fields")
                                   @QueryParam("textSearchField") String textSearchField,
                                   @ApiParam(value = "Filter by this text input")
                                   @QueryParam("textSearchInput") String textSearchInput,
                                   @ApiParam(value = "Filter CVSSv2 from this value")
                                   @QueryParam("cvssv2From") String cvssv2From,
                                   @ApiParam(value = "Filter CVSSv2 from this Value")
                                   @QueryParam("cvssv2To") String cvssv2To,
                                   @ApiParam(value = "Filter CVSSv3 from this value")
                                   @QueryParam("cvssv3From") String cvssv3From,
                                   @ApiParam(value = "Filter CVSSv3 from this Value")
                                   @QueryParam("cvssv3To") String cvssv3To) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Map<String, String> filters = new HashMap<>();
            filters.put("severity", severity);
            filters.put("analysisStatus", analysisStatus);
            filters.put("vendorResponse", vendorResponse);
            filters.put("publishDateFrom", publishDateFrom);
            filters.put("publishDateTo", publishDateTo);
            filters.put("attributedOnDateFrom", attributedOnDateFrom);
            filters.put("attributedOnDateTo", attributedOnDateTo);
            filters.put("textSearchField", textSearchField);
            filters.put("textSearchInput", textSearchInput);
            filters.put("cvssv2From", cvssv2From);
            filters.put("cvssv2To", cvssv2To);
            filters.put("cvssv3From", cvssv3From);
            filters.put("cvssv3To", cvssv3To);
            final PaginatedResult result = qm.getAllFindings(filters, showSuppressed, showInactive);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/grouped")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all findings grouped by vulnerability",
            response = GroupedFinding.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of findings"),
            notes = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getAllFindings(@ApiParam(value = "Show inactive projects")
                                   @QueryParam("showInactive") boolean showInactive,
                                   @ApiParam(value = "Filter by severity")
                                   @QueryParam("severity") String severity,
                                   @ApiParam(value = "Filter published from this date")
                                   @QueryParam("publishDateFrom") String publishDateFrom,
                                   @ApiParam(value = "Filter published to this date")
                                   @QueryParam("publishDateTo") String publishDateTo,
                                   @ApiParam(value = "Filter the text input in these fields")
                                   @QueryParam("textSearchField") String textSearchField,
                                   @ApiParam(value = "Filter by this text input")
                                   @QueryParam("textSearchInput") String textSearchInput,
                                   @ApiParam(value = "Filter CVSSv2 from this value")
                                   @QueryParam("cvssv2From") String cvssv2From,
                                   @ApiParam(value = "Filter CVSSv2 to this value")
                                   @QueryParam("cvssv2To") String cvssv2To,
                                   @ApiParam(value = "Filter CVSSv3 from this value")
                                   @QueryParam("cvssv3From") String cvssv3From,
                                   @ApiParam(value = "Filter CVSSv3 to this value")
                                   @QueryParam("cvssv3To") String cvssv3To,
                                   @ApiParam(value = "Filter occurrences in projects from this value")
                                   @QueryParam("occurrencesFrom") String occurrencesFrom,
                                   @ApiParam(value = "Filter occurrences in projects to this value")
                                   @QueryParam("occurrencesTo") String occurrencesTo) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Map<String, String> filters = new HashMap<>();
            filters.put("severity", severity);
            filters.put("publishDateFrom", publishDateFrom);
            filters.put("publishDateTo", publishDateTo);
            filters.put("textSearchField", textSearchField);
            filters.put("textSearchInput", textSearchInput);
            filters.put("cvssv2From", cvssv2From);
            filters.put("cvssv2To", cvssv2To);
            filters.put("cvssv3From", cvssv3From);
            filters.put("cvssv3To", cvssv3To);
            filters.put("occurrencesFrom", occurrencesFrom);
            filters.put("occurrencesTo", occurrencesTo);
            final PaginatedResult result = qm.getAllFindingsGroupedByVulnerability(filters, showInactive);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    private String generateSARIF(List<Finding> findings) throws IOException {
        final PebbleEngine engine = new PebbleEngine.Builder()
            .newLineTrimming(false)
            .defaultEscapingStrategy("json")
            .build();
        final PebbleTemplate sarifTemplate = engine.getTemplate("templates/findings/sarif.peb");

        final Map<String, Object> context = new HashMap<>();
        final About about = new About();

        // Using "vulnId" as key, forming a list of unique vulnerabilities across all findings
        // Also converts cweName to PascalCase, since it will be used as rule.name in the SARIF file
        List<Map<String, Object>> uniqueVulnerabilities = findings.stream()
            .collect(Collectors.toMap(
                finding -> finding.getVulnerability().get("vulnId"),
                FindingResource::convertCweNameToPascalCase,
                (existingVuln, replacementVuln) -> existingVuln))
            .values()
            .stream()
            .toList();

        context.put("findings", findings);
        context.put("dependencyTrackVersion", about.getVersion());
        context.put("uniqueVulnerabilities", uniqueVulnerabilities);

        try (final Writer writer = new StringWriter()) {
            sarifTemplate.evaluate(writer, context);
            return writer.toString();
        }
    }

    private static Map<String, Object> convertCweNameToPascalCase(Finding finding) {
        final Object cweName = finding.getVulnerability()
            .get("cweName");
        if (cweName != null) {
            final String pascalCasedCweName = WordUtils.capitalizeFully(cweName.toString()).replaceAll("\\s", "");
            finding.getVulnerability().put("cweName", pascalCasedCweName);
        }
        return finding.getVulnerability();
    }

}
