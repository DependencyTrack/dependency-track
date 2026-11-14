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
package org.dependencytrack.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import feign.Feign;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import feign.jaxrs3.JAXRS3Contract;
import org.dependencytrack.e2e.api.model.CreateNotificationRuleRequest;
import org.dependencytrack.e2e.api.model.EventTokenResponse;
import org.dependencytrack.e2e.api.model.NotificationPublisher;
import org.dependencytrack.e2e.api.model.NotificationRule;
import org.dependencytrack.e2e.api.model.UpdateNotificationRuleRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/** Verifies the public analysis API through a real server and local webhook delivery. */
class PolicyViolationUpdatedReviewedE2ET extends AbstractE2ET {

    private static final String KEV_A = "CVE-2021-44228";
    private static final String KEV_B = "CVE-2021-45046";
    private static final String KEV_C = "CVE-2099-00001";
    private static final String UPDATED = "GROUP_POLICY_VIOLATION_UPDATED";
    private static final String REVIEWED = "GROUP_POLICY_VIOLATION_UPDATED_REVIEWED";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .options(wireMockConfig().bindAddress("127.0.0.1").dynamicPort())
            .build();

    @Override
    @BeforeEach
    void beforeEach() throws Exception {
        Testcontainers.exposeHostPorts(wireMock.getRuntimeInfo().getHttpPort());
        super.beforeEach();
    }

    @Override
    protected void customizeApiServerContainer(GenericContainer<?> container) {
        // Only the host-side fixture can receive HTTP requests from this isolated server.
        container.withEnv("DT_OUTBOUND_ALLOWED_DESTINATIONS", "host.testcontainers.internal");
    }

    @ParameterizedTest
    @CsvSource({"APPROVED,false", "REJECTED,true", "APPROVED,true"})
    void shouldOptInToReviewedChangesThroughPublicAnalysisApi(String state, boolean suppressed) throws Exception {
        final String adminToken = apiV1Client.login("admin", "admin123");
        final var api = Feign.builder()
                .contract(new JAXRS3Contract())
                .encoder(new JacksonEncoder())
                .decoder(new JacksonDecoder())
                .requestInterceptor(request -> request.header("Authorization", "Bearer " + adminToken))
                .target(PolicyApi.class, "http://localhost:" + apiServerContainer.getFirstMappedPort());

        final UUID project = uuid(api.createProject(Map.of("name", "isolated-reviewed-kev", "version", "1")));
        final UUID component = uuid(api.createComponent(
                project, Map.of("name", "isolated-library", "version", "1", "classifier", "LIBRARY")));
        final UUID policy =
                uuid(api.createPolicy(Map.of("name", "KEV message", "operator", "ANY", "violationState", "FAIL")));
        api.createCondition(
                policy,
                Map.of(
                        "subject",
                        "EXPRESSION",
                        "operator",
                        "MATCHES",
                        "value",
                        "vulns.filter(v, v.is_kev).map(v, v.id).join(\",\")",
                        "violationType",
                        "SECURITY"));
        seedFindings(component);

        final NotificationPublisher publisher = apiV1Client.getAllNotificationPublishers().stream()
                .filter(candidate -> candidate.extensionName().equals("webhook"))
                .findFirst()
                .orElseThrow();
        createRule(publisher, "ordinary", Set.of("POLICY_VIOLATION", "POLICY_VIOLATION_UPDATED"), "/ordinary");
        wireMock.stubFor(
                post(urlPathEqualTo("/ordinary")).willReturn(aResponse().withStatus(204)));
        wireMock.stubFor(
                post(urlPathEqualTo("/reviewed")).willReturn(aResponse().withStatus(204)));

        setKevs(KEV_A);
        analyzeAndDrain(api, project);
        assertCounts(1, 0);
        final UUID violation = UUID.fromString(sql("SELECT \"UUID\" FROM \"POLICYVIOLATION\""));
        assertThat(notifications("/ordinary").getFirst().path("group").asText()).isEqualTo("GROUP_POLICY_VIOLATION");
        analyzeAndDrain(api, project);
        assertCounts(1, 0);

        // The default update subscription must retain its review/suppression exclusion.
        decide(api, component, violation, state, suppressed);
        setKevs(KEV_A, KEV_B);
        analyzeAndDrain(api, project);
        assertCounts(1, 0);
        assertDecision(state, suppressed);
        assertThat(sql("SELECT \"TEXT\" FROM \"POLICYVIOLATION\"")).isEqualTo(KEV_A + "," + KEV_B);

        // Explicit REST subscription does not replay the already-recorded transition.
        final NotificationRule reviewedRule =
                createRule(publisher, "reviewed", Set.of("POLICY_VIOLATION_UPDATED_REVIEWED"), "/reviewed");
        analyzeAndDrain(api, project);
        assertCounts(1, 0);

        setKevs(KEV_A, KEV_B, KEV_C);
        analyzeAndDrain(api, project);
        assertCounts(1, 1);
        assertUpdated(
                "/reviewed",
                REVIEWED,
                KEV_A + "," + KEV_B,
                KEV_A + "," + KEV_B + "," + KEV_C,
                violation,
                state,
                suppressed);
        assertDecision(state, suppressed);
        analyzeAndDrain(api, project);
        assertCounts(1, 1);

        // Subscribing to both event groups still classifies the same transition once.
        updateRule(reviewedRule, Set.of("POLICY_VIOLATION_UPDATED", "POLICY_VIOLATION_UPDATED_REVIEWED"), "/reviewed");
        setKevs(KEV_B, KEV_C);
        analyzeAndDrain(api, project);
        assertCounts(1, 2);
        assertUpdated(
                "/reviewed",
                REVIEWED,
                KEV_A + "," + KEV_B + "," + KEV_C,
                KEV_B + "," + KEV_C,
                violation,
                state,
                suppressed);
        assertDecision(state, suppressed);

        // Changing only a review decision is not a message-change event.
        decide(api, component, violation, "APPROVED", true);
        analyzeAndDrain(api, project);
        assertCounts(1, 2);
        decide(api, component, violation, "NOT_SET", false);
        analyzeAndDrain(api, project);
        assertCounts(1, 2);
        assertDecision("NOT_SET", false);

        setKevs(KEV_A, KEV_B, KEV_C);
        analyzeAndDrain(api, project);
        assertCounts(2, 3);
        final JsonNode ordinary = assertUpdated(
                "/ordinary",
                UPDATED,
                KEV_B + "," + KEV_C,
                KEV_A + "," + KEV_B + "," + KEV_C,
                violation,
                "NOT_SET",
                false);
        final JsonNode optedIn = assertUpdated(
                "/reviewed",
                UPDATED,
                KEV_B + "," + KEV_C,
                KEV_A + "," + KEV_B + "," + KEV_C,
                violation,
                "NOT_SET",
                false);
        assertThat(ordinary.path("id").asText()).isEqualTo(optedIn.path("id").asText());
        assertThat(sql("SELECT \"UUID\" FROM \"POLICYVIOLATION\"")).isEqualTo(violation.toString());
        analyzeAndDrain(api, project);
        assertCounts(2, 3);
    }

    private NotificationRule createRule(NotificationPublisher publisher, String name, Set<String> groups, String path) {
        final var rule = apiV1Client.createNotificationRule(new CreateNotificationRuleRequest(
                name, "PORTFOLIO", "INFORMATIONAL", new CreateNotificationRuleRequest.Publisher(publisher.uuid())));
        updateRule(rule, groups, path);
        return rule;
    }

    private void updateRule(NotificationRule rule, Set<String> groups, String path) {
        apiV1Client.updateNotificationRule(new UpdateNotificationRuleRequest(
                rule.uuid(),
                rule.name(),
                true,
                "PORTFOLIO",
                "INFORMATIONAL",
                groups,
                "{\"destinationUrl\":\"http://host.testcontainers.internal:%d%s\"}"
                        .formatted(wireMock.getPort(), path)));
    }

    private void decide(PolicyApi api, UUID component, UUID violation, String state, boolean suppressed) {
        api.decide(Map.of(
                "component",
                component.toString(),
                "policyViolation",
                violation.toString(),
                "analysisState",
                state,
                "isSuppressed",
                suppressed));
    }

    private void seedFindings(UUID component) throws Exception {
        sql("""
                INSERT INTO "VULNERABILITY" ("UUID", "VULNID", "SOURCE", "SEVERITY")
                VALUES (gen_random_uuid(), 'CVE-2021-44228', 'NVD', 'CRITICAL'),
                       (gen_random_uuid(), 'CVE-2021-45046', 'NVD', 'CRITICAL'),
                       (gen_random_uuid(), 'CVE-2099-00001', 'NVD', 'CRITICAL');
                INSERT INTO "COMPONENTS_VULNERABILITIES" ("COMPONENT_ID", "VULNERABILITY_ID")
                SELECT c."ID", v."ID" FROM "COMPONENT" c CROSS JOIN "VULNERABILITY" v
                 WHERE c."UUID" = '%s';
                INSERT INTO "FINDINGATTRIBUTION" (
                  "ANALYZERIDENTITY", "ATTRIBUTED_ON", "PROJECT_ID", "COMPONENT_ID", "VULNERABILITY_ID")
                SELECT 'none', now(), c."PROJECT_ID", c."ID", v."ID"
                  FROM "COMPONENT" c CROSS JOIN "VULNERABILITY" v
                 WHERE c."UUID" = '%s';
                """.formatted(component, component));
        assertThat(sql("SELECT COUNT(*) FROM \"FINDINGATTRIBUTION\"")).isEqualTo("3");
    }

    private void setKevs(String... ids) throws Exception {
        final String values = java.util.Arrays.stream(ids)
                .map(id -> "('local-test', 'NVD', '" + id + "')")
                .collect(java.util.stream.Collectors.joining(","));
        sql("DELETE FROM \"KEV_ASSERTION\" WHERE \"ASSERTER\" = 'local-test';"
                + "INSERT INTO \"KEV_ASSERTION\" (\"ASSERTER\", \"VULN_SOURCE\", \"VULN_ID\") VALUES " + values);
    }

    private void analyzeAndDrain(PolicyApi api, UUID project) throws Exception {
        final UUID run = UUID.fromString(api.analyze(project).token());
        await("real public analysis workflow completes")
                .atMost(Duration.ofSeconds(30))
                .untilAsserted(() -> assertThat(sql("SELECT status FROM dex_workflow_run WHERE id = '" + run + "'"))
                        .isEqualTo("COMPLETED"));
        // Outbox deletion and workflow creation share a transaction, so this has no relay gap.
        await("all durable webhook publishes complete")
                .atMost(Duration.ofSeconds(30))
                .untilAsserted(() -> assertThat(sql("""
                        SELECT NOT EXISTS (SELECT 1 FROM "NOTIFICATION_OUTBOX")
                           AND NOT EXISTS (SELECT 1 FROM dex_workflow_run
                                            WHERE workflow_name = 'publish-notification'
                                              AND status NOT IN ('COMPLETED', 'FAILED', 'CANCELLED'))
                        """)).isEqualTo("t"));
        assertThat(sql("SELECT COUNT(*) FROM dex_workflow_run WHERE workflow_name = 'publish-notification'"
                        + " AND status IN ('FAILED', 'CANCELLED')"))
                .isEqualTo("0");
    }

    private void assertDecision(String state, boolean suppressed) throws Exception {
        assertThat(sql("SELECT \"STATE\" || ':' || \"SUPPRESSED\"::text FROM \"VIOLATIONANALYSIS\""))
                .isEqualTo(state + ":" + suppressed);
    }

    private void assertCounts(int ordinary, int reviewed) throws IOException {
        assertThat(notifications("/ordinary")).hasSize(ordinary);
        assertThat(notifications("/reviewed")).hasSize(reviewed);
    }

    private JsonNode assertUpdated(
            String path,
            String group,
            String previous,
            String current,
            UUID violation,
            String state,
            boolean suppressed)
            throws IOException {
        final List<JsonNode> matching = notifications(path).stream()
                .filter(n -> n.path("group").asText().equals(group)
                        && n.path("subject").path("previousMessage").asText().equals(previous)
                        && n.path("subject").path("currentMessage").asText().equals(current))
                .toList();
        assertThat(matching).hasSize(1);
        final JsonNode notification = matching.getFirst();
        final JsonNode subject = notification.path("subject");
        assertThat(subject.path("policyViolation").path("uuid").asText()).isEqualTo(violation.toString());
        assertThat(subject.path("policyViolation").path("message").asText()).isEqualTo(current);
        assertThat(subject.path("changedAt").asText()).isNotBlank();
        if (group.equals(REVIEWED)) {
            assertThat(subject.path("analysisState").asText()).isEqualTo(state);
            assertThat(subject.path("suppressed").asBoolean()).isEqualTo(suppressed);
            assertThat(subject.has("suppressed")).isTrue();
        } else {
            assertThat(subject.has("analysisState")).isFalse();
            assertThat(subject.has("suppressed")).isFalse();
        }
        return notification;
    }

    private List<JsonNode> notifications(String path) throws IOException {
        final var result = new ArrayList<JsonNode>();
        for (final var request : wireMock.findAll(postRequestedFor(urlPathEqualTo(path)))) {
            result.add(MAPPER.readTree(request.getBodyAsString()).path("notification"));
        }
        return result;
    }

    private String sql(String statement) throws Exception {
        final var result = postgresContainer.execInContainer(
                "psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "dtrack", "-d", "dtrack", "-c", statement);
        assertThat(result.getExitCode()).withFailMessage(result.getStderr()).isZero();
        return result.getStdout().strip();
    }

    private static UUID uuid(Map<String, Object> object) {
        return UUID.fromString(String.valueOf(object.get("uuid")));
    }

    @Path("/api/v1")
    public interface PolicyApi {
        @PUT
        @Path("/project")
        @Consumes(MediaType.APPLICATION_JSON)
        @Produces(MediaType.APPLICATION_JSON)
        Map<String, Object> createProject(Map<String, Object> request);

        @PUT
        @Path("/component/project/{uuid}")
        @Consumes(MediaType.APPLICATION_JSON)
        @Produces(MediaType.APPLICATION_JSON)
        Map<String, Object> createComponent(@PathParam("uuid") UUID project, Map<String, Object> request);

        @PUT
        @Path("/policy")
        @Consumes(MediaType.APPLICATION_JSON)
        @Produces(MediaType.APPLICATION_JSON)
        Map<String, Object> createPolicy(Map<String, Object> request);

        @PUT
        @Path("/policy/{uuid}/condition")
        @Consumes(MediaType.APPLICATION_JSON)
        @Produces(MediaType.APPLICATION_JSON)
        Map<String, Object> createCondition(@PathParam("uuid") UUID policy, Map<String, Object> request);

        @PUT
        @Path("/violation/analysis")
        @Consumes(MediaType.APPLICATION_JSON)
        @Produces(MediaType.APPLICATION_JSON)
        Map<String, Object> decide(Map<String, Object> request);

        @POST
        @Path("/finding/project/{uuid}/analyze")
        @Consumes(MediaType.APPLICATION_JSON)
        @Produces(MediaType.APPLICATION_JSON)
        EventTokenResponse analyze(@PathParam("uuid") UUID project);
    }
}
