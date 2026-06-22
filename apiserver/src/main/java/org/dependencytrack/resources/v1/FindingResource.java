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

import alpine.model.About;
import alpine.server.auth.PermissionRequired;
import com.github.packageurl.PackageURL;
import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.analysis.AnalyzeProjectWorkflow;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.integrations.FindingPackagingFormat;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.GroupedFinding;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.FindingDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.pkgmetadata.ResolvePackageMetadataWorkflow;
import org.dependencytrack.proto.internal.workflow.v1.AnalyzeProjectWorkflowArg;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.BomUploadResponse;
import org.dependencytrack.resources.v1.vo.FindingResponse;
import org.dependencytrack.util.PersistenceUtil;
import org.dependencytrack.util.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_TRIGGERED_BY;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.proto.internal.workflow.v1.AnalysisTrigger.ANALYSIS_TRIGGER_MANUAL;

/**
 * JAX-RS resources for processing findings.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@Path("/v1/finding")
@Tag(name = "finding")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class FindingResource extends AbstractApiResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(FindingResource.class);
    public static final String MEDIA_TYPE_SARIF_JSON = "application/sarif+json";

    private final DexEngine dexEngine;

    @Inject
    FindingResource(DexEngine dexEngine) {
        this.dexEngine = dexEngine;
    }

    @GET
    @Path("/project/{uuid}")
    @Produces({MediaType.APPLICATION_JSON, MEDIA_TYPE_SARIF_JSON})
    @Operation(
            summary = "Returns a list of all findings for a specific project or generates SARIF file if Accept: application/sarif+json header is provided",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all findings for a specific project, or a SARIF file",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of findings", schema = @Schema(format = "integer")),
                    content = {
                            @Content(array = @ArraySchema(schema = @Schema(implementation = FindingResponse.class)), mediaType = MediaType.APPLICATION_JSON),
                            @Content(schema = @Schema(type = "string"), mediaType = MEDIA_TYPE_SARIF_JSON)
                    }
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PaginatedApi
    @Parameter(
            name = "searchText",
            in = ParameterIn.QUERY,
            description = """
                    Case-insensitive substring filter matched against component name, \
                    component group, and vulnerability ID. Additionally matched as an \
                    exact value against component UUID, vulnerability UUID, and the \
                    `componentUuid:vulnerabilityUuid` pair."""
    )
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getFindingsByProject(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true)
                                         @PathParam("uuid") @ValidUuid String uuid,
                                         @Parameter(description = "Optionally includes suppressed findings")
                                         @QueryParam("suppressed") boolean suppressed,
                                         @Parameter(description = "Optionally limit findings to specific sources of vulnerability intelligence")
                                         @QueryParam("source") Vulnerability.Source source,
                                         @HeaderParam("accept") String acceptHeader,
                                         @Parameter(description = "Whether to include only projects with existing analysis.")
                                         @QueryParam("hasAnalysis") final Boolean hasAnalysis,
                                         @Parameter(description = "Filter EPSS score from this value (inclusive)")
                                         @QueryParam("epssFrom") final BigDecimal epssFrom,
                                         @Parameter(description = "Filter EPSS score to this value (inclusive)")
                                         @QueryParam("epssTo") final BigDecimal epssTo) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                requireAccess(qm, project);
                final String rawFilter = getAlpineRequest().getFilter();
                final String searchText =
                        (rawFilter != null && !rawFilter.isBlank())
                                ? PersistenceUtil.escapeLikePattern(rawFilter)
                                : null;
                List<FindingDao.FindingRow> findingRows = withJdbiHandle(getAlpineRequest(), handle -> {
                    final var dao = handle.attach(FindingDao.class);
                    return dao.withJitDisabled(
                            () -> dao.getFindingsByProject(
                                    project.getId(),
                                    /* includeInactive */ false,
                                    suppressed,
                                    searchText,
                                    hasAnalysis,
                                    source != null ? source.name() : null,
                                    epssFrom,
                                    epssTo));
                });
                final long totalCount = findingRows.isEmpty() ? 0 : findingRows.getFirst().totalCount();
                List<Finding> findings = findingRows.stream().map(Finding::new).toList();
                findings = mapComponentLatestVersion(findings);
                if (acceptHeader != null && acceptHeader.contains(MEDIA_TYPE_SARIF_JSON)) {
                    try {
                        return Response.ok(generateSARIF(findings), MEDIA_TYPE_SARIF_JSON)
                                .header("content-disposition", "attachment; filename=\"findings-" + uuid + ".sarif\"")
                                .build();
                    } catch (IOException ioException) {
                        LOGGER.error(ioException.getMessage(), ioException);
                        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("An error occurred while generating SARIF file").build();
                    }
                }
                return Response.ok(findings.stream().map(FindingResponse::of).toList())
                        .header(TOTAL_COUNT_HEADER, totalCount)
                        .build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/project/{uuid}/export")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns the findings for the specified project as FPF",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The findings for the specified project as FPF",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response exportFindingsByProject(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true)
                                            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                requireAccess(qm, project);
                final List<Finding> findings = withJdbiHandle(getAlpineRequest(), handle ->
                        handle.attach(FindingDao.class).getFindings(project.getId(), false));
                final FindingPackagingFormat fpf = new FindingPackagingFormat(UUID.fromString(uuid), findings);
                final Response.ResponseBuilder rb = Response.ok(fpf.getDocument(), "application/json");
                rb.header("Content-Disposition", "inline; filename=findings-" + uuid + ".fpf");
                return rb.build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @POST
    @Path("/project/{uuid}/analyze")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Triggers Vulnerability Analysis on a specific project",
            description = "<p>Requires permission <strong>VULNERABILITY_ANALYSIS</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token to be used for checking analysis progress",
                    content = @Content(schema = @Schema(implementation = BomUploadResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS)
    public Response analyzeProject(
            @Parameter(description = "The UUID of the project to analyze", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        useJdbiHandle(handle -> requireProjectAccess(handle, UUID.fromString(uuid)));

        final UUID runId = dexEngine.createRun(
                new CreateWorkflowRunRequest<>(AnalyzeProjectWorkflow.class)
                        .withWorkflowInstanceId("analyze-project-manual:" + uuid)
                        .withConcurrencyKey("analyze-project:" + uuid)
                        .withLabels(Map.ofEntries(
                                Map.entry(WF_LABEL_PROJECT_UUID, uuid),
                                Map.entry(WF_LABEL_TRIGGERED_BY, getPrincipal().getName())))
                        .withPriority(75)
                        .withArgument(
                                AnalyzeProjectWorkflowArg.newBuilder()
                                        .setProjectUuid(uuid)
                                        .setTrigger(ANALYSIS_TRIGGER_MANUAL)
                                        .build()));
        if (runId == null) {
            return Response.status(Response.Status.CONFLICT).build();
        }

        dexEngine.createRun(
                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class)
                        .withWorkflowInstanceId(ResolvePackageMetadataWorkflow.INSTANCE_ID));

        return Response.ok(Map.of("token", runId)).build();
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all findings",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all findings",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of findings", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = FindingResponse.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
    })
    @PaginatedApi
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getAllFindings(@Parameter(description = "Show inactive projects")
                                   @QueryParam("showInactive") boolean showInactive,
                                   @Parameter(description = "Show suppressed findings")
                                   @QueryParam("showSuppressed") boolean showSuppressed,
                                   @Parameter(description = "Filter by severity")
                                   @QueryParam("severity") String severity,
                                   @Parameter(description = "Filter by analysis status")
                                   @QueryParam("analysisStatus") String analysisStatus,
                                   @Parameter(description = "Filter by vendor response")
                                   @QueryParam("vendorResponse") String vendorResponse,
                                   @Parameter(description = "Filter published from this date")
                                   @QueryParam("publishDateFrom") String publishDateFrom,
                                   @Parameter(description = "Filter published to this date")
                                   @QueryParam("publishDateTo") String publishDateTo,
                                   @Parameter(description = "Filter attributed on from this date")
                                   @QueryParam("attributedOnDateFrom") String attributedOnDateFrom,
                                   @Parameter(description = "Filter attributed on to this date")
                                   @QueryParam("attributedOnDateTo") String attributedOnDateTo,
                                   @Parameter(description = "Filter the text input in these fields")
                                   @QueryParam("textSearchField") String textSearchField,
                                   @Parameter(description = "Filter by this text input")
                                   @QueryParam("textSearchInput") String textSearchInput,
                                   @Parameter(description = "Filter CVSSv2 from this value")
                                   @QueryParam("cvssv2From") String cvssv2From,
                                   @Parameter(description = "Filter CVSSv2 from this Value")
                                   @QueryParam("cvssv2To") String cvssv2To,
                                   @Parameter(description = "Filter CVSSv3 from this value")
                                   @QueryParam("cvssv3From") String cvssv3From,
                                   @Parameter(description = "Filter CVSSv3 from this Value")
                                   @QueryParam("cvssv3To") String cvssv3To,
                                   @Parameter(description = "Filter CVSSv4 from this value")
                                   @QueryParam("cvssv4From") String cvssv4From,
                                   @Parameter(description = "Filter CVSSv4 to this value")
                                   @QueryParam("cvssv4To") String cvssv4To,
                                   @Parameter(description = "Filter EPSS from this value")
                                   @QueryParam("epssFrom") String epssFrom,
                                   @Parameter(description = "Filter EPSS to this value")
                                   @QueryParam("epssTo") String epssTo,
                                   @Parameter(description = "Filter EPSS Percentile from this value")
                                   @QueryParam("epssPercentileFrom") String epssPercentileFrom,
                                   @Parameter(description = "Filter EPSS Percentile to this value")
                                   @QueryParam("epssPercentileTo") String epssPercentileTo) {
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
        filters.put("cvssv4From", cvssv4From);
        filters.put("cvssv4To", cvssv4To);
        filters.put("epssFrom", epssFrom);
        filters.put("epssTo", epssTo);
        filters.put("epssPercentileFrom", epssPercentileFrom);
        filters.put("epssPercentileTo", epssPercentileTo);
        List<FindingDao.FindingRow> findingRows = withJdbiHandle(getAlpineRequest(), handle -> handle.attach(FindingDao.class)
                .getAllFindings(filters, showSuppressed, showInactive, getAlpineRequest().getOrderBy()));
        final long totalCount = findingRows.isEmpty() ? 0 : findingRows.getFirst().totalCount();
        List<Finding> findings = findingRows.stream().map(Finding::new).toList();
        findings = mapComponentLatestVersion(findings);
        return Response.ok(findings.stream().map(FindingResponse::of).toList())
                .header(TOTAL_COUNT_HEADER, totalCount)
                .build();
    }

    @GET
    @Path("/grouped")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all findings grouped by vulnerability",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all findings grouped by vulnerability",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of findings", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Finding.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PaginatedApi
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getAllFindings(@Parameter(description = "Show inactive projects")
                                   @QueryParam("showInactive") boolean showInactive,
                                   @Parameter(description = "Filter by severity")
                                   @QueryParam("severity") String severity,
                                   @Parameter(description = "Filter published from this date")
                                   @QueryParam("publishDateFrom") String publishDateFrom,
                                   @Parameter(description = "Filter published to this date")
                                   @QueryParam("publishDateTo") String publishDateTo,
                                   @Parameter(description = "Filter the text input in these fields")
                                   @QueryParam("textSearchField") String textSearchField,
                                   @Parameter(description = "Filter by this text input")
                                   @QueryParam("textSearchInput") String textSearchInput,
                                   @Parameter(description = "Filter CVSSv2 from this value")
                                   @QueryParam("cvssv2From") String cvssv2From,
                                   @Parameter(description = "Filter CVSSv2 to this value")
                                   @QueryParam("cvssv2To") String cvssv2To,
                                   @Parameter(description = "Filter CVSSv3 from this value")
                                   @QueryParam("cvssv3From") String cvssv3From,
                                   @Parameter(description = "Filter CVSSv3 to this value")
                                   @QueryParam("cvssv3To") String cvssv3To,
                                   @Parameter(description = "Filter CVSSv4 from this value")
                                   @QueryParam("cvssv4From") String cvssv4From,
                                   @Parameter(description = "Filter CVSSv4 to this value")
                                   @QueryParam("cvssv4To") String cvssv4To,
                                   @Parameter(description = "Filter EPSS from this value")
                                   @QueryParam("epssFrom") String epssFrom,
                                   @Parameter(description = "Filter EPSS to this value")
                                   @QueryParam("epssTo") String epssTo,
                                   @Parameter(description = "Filter EPSS Percentile from this value")
                                   @QueryParam("epssPercentileFrom") String epssPercentileFrom,
                                   @Parameter(description = "Filter EPSS Percentile to this value")
                                   @QueryParam("epssPercentileTo") String epssPercentileTo,
                                   @Parameter(description = "Filter occurrences in projects from this value")
                                   @QueryParam("occurrencesFrom") String occurrencesFrom,
                                   @Parameter(description = "Filter occurrences in projects to this value")
                                   @QueryParam("occurrencesTo") String occurrencesTo) {
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
        filters.put("cvssv4From", cvssv4From);
        filters.put("cvssv4To", cvssv4To);
        filters.put("epssFrom", epssFrom);
        filters.put("epssTo", epssTo);
        filters.put("epssPercentileFrom", epssPercentileFrom);
        filters.put("epssPercentileTo", epssPercentileTo);
        filters.put("occurrencesFrom", occurrencesFrom);
        filters.put("occurrencesTo", occurrencesTo);
        List<FindingDao.GroupedFindingRow> findingRows = withJdbiHandle(getAlpineRequest(), handle -> handle.attach(FindingDao.class)
                .getGroupedFindings(filters, showInactive));
        final long totalCount = findingRows.isEmpty() ? 0 : findingRows.getFirst().totalCount();
        List<GroupedFinding> findings = findingRows.stream().map(GroupedFinding::new).toList();
        return Response.ok(findings).header(TOTAL_COUNT_HEADER, totalCount).build();
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
        List<Map<String, Object>> uniqueVulnerabilities = findings.stream()
                .collect(Collectors.toMap(
                        finding -> finding.getVulnerability().get("vulnId"),
                        Finding::getVulnerability,
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

    public static List<Finding> mapComponentLatestVersion(List<Finding> findingList) {
        final Map<String, List<Finding>> findingsByPurlPackage = findingList.stream()
                .filter(finding -> finding.getComponent().get("purl") != null)
                .map(finding -> {
                    final PackageURL purl = PurlUtil.silentPurl((String) finding.getComponent().get("purl"));
                    if (purl == null) {
                        return null;
                    }

                    final var repositoryType = RepositoryType.resolve(purl);
                    if (repositoryType == RepositoryType.UNSUPPORTED) {
                        return null;
                    }
                    return Map.entry(PurlUtil.purlPackageOnly(purl), finding);
                })
                .filter(Objects::nonNull)
                .collect(Collectors.groupingBy(
                        Map.Entry::getKey,
                        Collectors.mapping(Map.Entry::getValue, Collectors.toList())
                ));
        final List<PackageMetadata> packageMetadataList = withJdbiHandle(handle ->
                new PackageMetadataDao(handle).getAll(findingsByPurlPackage.keySet()));
        packageMetadataList.forEach(packageMetadata -> {
            final List<Finding> affectedFindings =
                    findingsByPurlPackage.get(packageMetadata.purl().canonicalize());
            if (affectedFindings != null && packageMetadata.latestVersion() != null) {
                for (final Finding finding : affectedFindings) {
                    finding.getComponent().put("latestVersion", packageMetadata.latestVersion());
                }
            }
        });
        return findingList;
    }
}
