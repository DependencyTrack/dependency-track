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

import alpine.model.IConfigProperty;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthFeature;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.jdbi.MetricsTestDao;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BADGE_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

public class BadgeResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(BadgeResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class));

    @BeforeEach
    @Override
    public void before() throws Exception {
        super.before();
        qm.createConfigProperty(GENERAL_BADGE_ENABLED.getGroupName(), GENERAL_BADGE_ENABLED.getPropertyName(), "true", IConfigProperty.PropertyType.BOOLEAN, "Public access to badge enabled");
    }

    @Test
    public void shouldReturnVulnBadgeByUuid() {
        final Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, null, false);
        final Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid())
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("image/svg+xml");
        assertThat(isLikelySvg(getPlainTextBody(response))).isTrue();
    }

    @Test
    public void shouldReturn404ForVulnBadgeByUuidWhenProjectNotFound() {
        final Response response = jersey.target(V1_BADGE + "/vulns/project/" + UUID.randomUUID())
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void shouldReturn403ForVulnBadgeByUuidWhenDisabled() {
        qm.getConfigProperty(GENERAL_BADGE_ENABLED.getGroupName(), GENERAL_BADGE_ENABLED.getPropertyName()).setPropertyValue("false");
        final Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, null, false);
        final Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid())
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    public void shouldReturnVulnBadgeByNameAndVersion() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, null, false);
        final Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0")
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("image/svg+xml");
        assertThat(isLikelySvg(getPlainTextBody(response))).isTrue();
    }

    @Test
    public void shouldReturn404ForVulnBadgeByNameAndVersionWhenProjectNotFound() {
        final Response response = jersey.target(V1_BADGE + "/vulns/project/DoesNotExist/1.0.0")
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void shouldReturn404ForVulnBadgeByNameAndVersionWhenVersionNotFound() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, null, false);
        final Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/9.9.9")
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void shouldReturn403ForVulnBadgeByNameAndVersionWhenDisabled() {
        qm.getConfigProperty(GENERAL_BADGE_ENABLED.getGroupName(), GENERAL_BADGE_ENABLED.getPropertyName()).setPropertyValue("false");
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, null, false);
        final Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0")
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    public void shouldReturnViolationsBadgeByUuid() {
        final Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, null, false);
        final Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid())
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("image/svg+xml");
        assertThat(isLikelySvg(getPlainTextBody(response))).isTrue();
    }

    @Test
    public void shouldReturn404ForViolationsBadgeByUuidWhenProjectNotFound() {
        final Response response = jersey.target(V1_BADGE + "/violations/project/" + UUID.randomUUID())
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void shouldReturn403ForViolationsBadgeByUuidWhenDisabled() {
        qm.getConfigProperty(GENERAL_BADGE_ENABLED.getGroupName(), GENERAL_BADGE_ENABLED.getPropertyName()).setPropertyValue("false");
        final Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, null, false);
        final Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid())
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    public void shouldReturnViolationsBadgeByNameAndVersion() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, null, false);
        final Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0")
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("image/svg+xml");
        assertThat(isLikelySvg(getPlainTextBody(response))).isTrue();
    }

    @Test
    public void shouldReturn404ForViolationsBadgeByNameAndVersionWhenProjectNotFound() {
        final Response response = jersey.target(V1_BADGE + "/violations/project/DoesNotExist/1.0.0")
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void shouldReturn404ForViolationsBadgeByNameAndVersionWhenVersionNotFound() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, null, false);
        final Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/9.9.9")
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void shouldReturn403ForViolationsBadgeByNameAndVersionWhenDisabled() {
        qm.getConfigProperty(GENERAL_BADGE_ENABLED.getGroupName(), GENERAL_BADGE_ENABLED.getPropertyName()).setPropertyValue("false");
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, null, false);
        final Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0")
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    public void shouldReturnVulnBadgeWithAggregatedMetricsForCollectionProjectByUuid() {
        final Project collection = createCollectionProjectWithChildMetrics();

        final Response response = jersey
                .target(V1_BADGE + "/vulns/project/" + collection.getUuid())
                .request()
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("image/svg+xml");
        assertThatBodyContainsAggregatedVulnMetrics(getPlainTextBody(response));
    }

    @Test
    public void shouldReturnVulnBadgeWithAggregatedMetricsForCollectionProjectByNameAndVersion() {
        final Project collection = createCollectionProjectWithChildMetrics();

        final Response response = jersey
                .target(V1_BADGE
                        + "/vulns/project/"
                        + collection.getName()
                        + "/"
                        + collection.getVersion())
                .request()
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("image/svg+xml");
        assertThatBodyContainsAggregatedVulnMetrics(getPlainTextBody(response));
    }

    @Test
    public void shouldReturnViolationsBadgeWithAggregatedMetricsForCollectionProjectByUuid() {
        final Project collection = createCollectionProjectWithChildMetrics();

        final Response response = jersey
                .target(V1_BADGE + "/violations/project/" + collection.getUuid())
                .request()
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("image/svg+xml");
        assertThatBodyContainsAggregatedViolationMetrics(getPlainTextBody(response));
    }

    @Test
    public void shouldReturnViolationsBadgeWithAggregatedMetricsForCollectionProjectByNameAndVersion() {
        final Project collection = createCollectionProjectWithChildMetrics();

        final Response response = jersey
                .target(V1_BADGE
                        + "/violations/project/"
                        + collection.getName()
                        + "/"
                        + collection.getVersion())
                .request()
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("image/svg+xml");
        assertThatBodyContainsAggregatedViolationMetrics(getPlainTextBody(response));
    }

    private Project createCollectionProjectWithChildMetrics() {
        final var parent = new Project();
        parent.setName("acme-collection");
        parent.setVersion("1.0.0");
        parent.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.persist(parent);

        final var childA = new Project();
        childA.setName("acme-child-a");
        childA.setParent(parent);
        qm.persist(childA);

        final var childB = new Project();
        childB.setName("acme-child-b");
        childB.setParent(parent);
        qm.persist(childB);

        useJdbiHandle(handle -> {
            final var dao = handle.attach(MetricsTestDao.class);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", LocalDate.now(ZoneOffset.UTC));
            final Date now = Date.from(Instant.now());

            final var metricsA = new ProjectMetrics();
            metricsA.setProjectId(childA.getId());
            metricsA.setCritical(2);
            metricsA.setHigh(3);
            metricsA.setMedium(1);
            metricsA.setVulnerabilities(6);
            metricsA.setPolicyViolationsTotal(6);
            metricsA.setPolicyViolationsFail(2);
            metricsA.setPolicyViolationsWarn(3);
            metricsA.setPolicyViolationsInfo(1);
            metricsA.setFirstOccurrence(now);
            metricsA.setLastOccurrence(now);
            dao.createProjectMetrics(metricsA);

            final var metricsB = new ProjectMetrics();
            metricsB.setProjectId(childB.getId());
            metricsB.setCritical(1);
            metricsB.setHigh(4);
            metricsB.setMedium(5);
            metricsB.setVulnerabilities(10);
            metricsB.setPolicyViolationsTotal(4);
            metricsB.setPolicyViolationsFail(1);
            metricsB.setPolicyViolationsWarn(1);
            metricsB.setPolicyViolationsInfo(2);
            metricsB.setFirstOccurrence(now);
            metricsB.setLastOccurrence(now);
            dao.createProjectMetrics(metricsB);
        });

        return parent;
    }

    private void assertThatBodyContainsAggregatedVulnMetrics(String body) {
        assertThat(isLikelySvg(body)).isTrue();
        assertThat(body)
                .contains(">3</text>")
                .contains(">7</text>")
                .contains(">6</text>");
    }

    private void assertThatBodyContainsAggregatedViolationMetrics(String body) {
        assertThat(isLikelySvg(body)).isTrue();
        assertThat(body)
                .contains(">3</text>")
                .contains(">4</text>")
                .contains(">3</text>");
    }

    private boolean isLikelySvg(String body) {
        try {
            final InputStream is = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
            final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            final DocumentBuilder db = dbf.newDocumentBuilder();
            db.parse(is);
            return body.startsWith("<svg");
        } catch (Exception e) {
            return false;
        }
    }
}
