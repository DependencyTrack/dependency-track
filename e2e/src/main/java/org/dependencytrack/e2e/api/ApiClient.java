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
package org.dependencytrack.e2e.api;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import org.dependencytrack.e2e.api.model.Analysis;
import org.dependencytrack.e2e.api.model.ApiKey;
import org.dependencytrack.e2e.api.model.BomUploadRequest;
import org.dependencytrack.e2e.api.model.CreateNotificationRuleRequest;
import org.dependencytrack.e2e.api.model.CreateTeamRequest;
import org.dependencytrack.e2e.api.model.CreateVulnerabilityRequest;
import org.dependencytrack.e2e.api.model.EventProcessingResponse;
import org.dependencytrack.e2e.api.model.EventTokenResponse;
import org.dependencytrack.e2e.api.model.Finding;
import org.dependencytrack.e2e.api.model.NotificationPublisher;
import org.dependencytrack.e2e.api.model.NotificationRule;
import org.dependencytrack.e2e.api.model.Page;
import org.dependencytrack.e2e.api.model.Project;
import org.dependencytrack.e2e.api.model.Team;
import org.dependencytrack.e2e.api.model.UpdateExtensionConfigRequest;
import org.dependencytrack.e2e.api.model.UpdateNotificationRuleRequest;
import org.dependencytrack.e2e.api.model.VulnPolicyBundleSyncStatus;
import org.dependencytrack.e2e.api.model.VulnerabilityPolicy;

import java.util.List;
import java.util.UUID;

@Path("/api")
public interface ApiClient {

    @POST
    @Path("/v1/user/forceChangePassword")
    @Produces(MediaType.WILDCARD)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    void forcePasswordChange(
            @FormParam("username") String username,
            @FormParam("password") String password,
            @FormParam("newPassword") String newPassword,
            @FormParam("confirmPassword") String confirmPassword);

    @POST
    @Path("/v1/user/login")
    @Produces(MediaType.WILDCARD)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    String login(
            @FormParam("username") String username,
            @FormParam("password") String password);

    @PUT
    @Path("/v1/team")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    Team createTeam(CreateTeamRequest request);

    @PUT
    @Path("/v1/team/{uuid}/key")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.WILDCARD)
    ApiKey createApiKey(@PathParam("uuid") UUID teamUuid);

    @POST
    @Path("/v1/permission/{permission}/team/{uuid}")
    @Produces(MediaType.WILDCARD)
    @Consumes(MediaType.APPLICATION_JSON)
    Team addPermissionToTeam(
            @PathParam("uuid") UUID teamUuid,
            @PathParam("permission") String permission);

    @PUT
    @Path("/v1/bom")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    EventTokenResponse uploadBom(BomUploadRequest request);

    @GET
    @Path("/v1/event/token/{token}")
    @Produces(MediaType.WILDCARD)
    @Consumes(MediaType.WILDCARD)
    EventProcessingResponse isEventBeingProcessed(@PathParam("token") String token);

    @PUT
    @Path("/v1/vulnerability")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    void createVulnerability(CreateVulnerabilityRequest request);

    @GET
    @Path("/v1/finding/project/{uuid}")
    @Produces(MediaType.WILDCARD)
    @Consumes(MediaType.APPLICATION_JSON)
    List<Finding> getFindings(
            @PathParam("uuid") UUID projectUuid,
            @QueryParam("suppressed") boolean includeSuppressed);

    @GET
    @Path("/v1/project/lookup")
    @Produces(MediaType.WILDCARD)
    @Consumes(MediaType.APPLICATION_JSON)
    Project lookupProject(
            @QueryParam("name") String name,
            @QueryParam("version") String version);

    @GET
    @Path("/v1/notification/publisher")
    @Produces(MediaType.WILDCARD)
    @Consumes(MediaType.APPLICATION_JSON)
    List<NotificationPublisher> getAllNotificationPublishers();

    @PUT
    @Path("/v1/notification/rule")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    NotificationRule createNotificationRule(CreateNotificationRuleRequest request);

    @POST
    @Path("/v1/notification/rule")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    NotificationRule updateNotificationRule(UpdateNotificationRuleRequest request);

    @GET
    @Path("/v2/vuln-policies")
    @Produces(MediaType.WILDCARD)
    @Consumes(MediaType.APPLICATION_JSON)
    Page<VulnerabilityPolicy> getAllVulnerabilityPolicies();

    @POST
    @Path("/v2/vuln-policy-bundles/{uuid}/sync-runs")
    void triggerVulnPolicyBundleSync(@PathParam("uuid") UUID uuid);

    @GET
    @Path("/v2/vuln-policy-bundles/{uuid}/sync-runs/latest")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    VulnPolicyBundleSyncStatus getVulnPolicyBundleSyncStatus(@PathParam("uuid") UUID uuid);

    @GET
    @Path("/v1/analysis")
    @Produces(MediaType.WILDCARD)
    @Consumes(MediaType.APPLICATION_JSON)
    Analysis getAnalysis(
            @QueryParam("project") UUID projectUuid,
            @QueryParam("component") UUID componentUuid,
            @QueryParam("vulnerability") UUID vulnUuid);

    @POST
    @Path("/v1/finding/project/{uuid}/analyze")
    @Produces(MediaType.WILDCARD)
    @Consumes(MediaType.APPLICATION_JSON)
    EventTokenResponse analyzeProject(@PathParam("uuid") UUID projectUuid);

    @PUT
    @Path("/v2/extension-points/{extensionPoint}/extensions/{extension}/config")
    @Produces(MediaType.WILDCARD)
    @Consumes(MediaType.APPLICATION_JSON)
    void updateExtensionConfig(
            @PathParam("extensionPoint") String extensionPoint,
            @PathParam("extension") String extension,
            UpdateExtensionConfigRequest request);

}
