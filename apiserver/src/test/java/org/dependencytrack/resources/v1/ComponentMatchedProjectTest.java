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

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthFeature;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import jakarta.ws.rs.core.Response;

import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.resources.v1.ComponentResource.MATCHED_PROJECT_FORBIDDEN_DETAIL;
import static org.mockito.Mockito.mock;

public class ComponentMatchedProjectTest extends ResourceTest {

    private static final String COMPONENT_CPE_22 = "cpe:/a:acme:acme-lib:2.0";
    private static final String PROJECT_CPE_23 = "cpe:2.3:a:acme:acme-lib:2.0:*:*:*:*:*:*:*";
    private static final String OTHER_CPE_23 = "cpe:2.3:a:acme:other-lib:2.0:*:*:*:*:*:*:*";
    private static final String LIB_PURL = "pkg:maven/com.acme/acme-lib@2.0";
    private static final String OTHER_PURL = "pkg:maven/com.acme/other-lib@2.0";

    private static final DexEngine DEX_ENGINE_MOCK = mock(DexEngine.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig(ComponentResource.class)
            .register(ApiFilter.class)
            .register(AuthFeature.class)
            .register(new AbstractBinder() {
                @Override
                protected void configure() {
                    bind(DEX_ENGINE_MOCK).to(DexEngine.class);
                }
            }));

    @Test
    public void matchedProjectReturnsPath() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project parent = createProject("acme-app", "1.0", "cpe:2.3:a:acme:acme-app:1.0:*:*:*:*:*:*:*");
        final Component component = createComponent(parent, "acme-lib", "2.0", COMPONENT_CPE_22);
        final Project matched = createProject("acme-lib", "2.0", PROJECT_CPE_23);

        final Response response = getMatchedProject(component.getUuid());

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "path": "/projects/%s"
                }
                """.formatted(matched.getUuid()));
    }

    @Test
    public void matchedProjectNotFoundWhenCpeDiffers() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project parent = createProject("acme-app", "1.0", null);
        final Component component = createComponent(parent, "acme-lib", "2.0", COMPONENT_CPE_22);
        createProject("acme-lib", "2.0", OTHER_CPE_23);

        assertNotFound(getMatchedProject(component.getUuid()));
    }

    @Test
    public void matchedProjectNotFoundWhenCpeMissing() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project parent = createProject("acme-app", "1.0", null);
        final Component component = createComponent(parent, "acme-lib", "2.0", null);
        createProject("acme-lib", "2.0", PROJECT_CPE_23);

        assertNotFound(getMatchedProject(component.getUuid()));
    }

    @Test
    public void matchedProjectNotFoundWhenProjectMissing() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project parent = createProject("acme-app", "1.0", null);
        final Component component = createComponent(parent, "acme-lib", "2.0", COMPONENT_CPE_22);

        assertNotFound(getMatchedProject(component.getUuid()));
    }

    @Test
    public void matchedProjectNotFoundWhenComponentMissing() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        assertNotFound(getMatchedProject(UUID.randomUUID()));
    }

    @Test
    public void matchedProjectForbiddenWhenOwningProjectInaccessible() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();
        final Project parent = createProject("acme-app", "1.0", null);
        final Component component = createComponent(parent, "acme-lib", "2.0", COMPONENT_CPE_22);
        final Project matched = createProject("acme-lib", "2.0", PROJECT_CPE_23);
        matched.addAccessTeam(super.team);

        assertForbidden(getMatchedProject(component.getUuid()));
    }

    @Test
    public void matchedProjectForbiddenWhenMatchedProjectInaccessible() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();
        final Project parent = createProject("acme-app", "1.0", null);
        parent.addAccessTeam(super.team);
        final Component component = createComponent(parent, "acme-lib", "2.0", COMPONENT_CPE_22);
        createProject("acme-lib", "2.0", PROJECT_CPE_23);

        assertForbidden(getMatchedProject(component.getUuid()));
    }

    @Test
    public void matchedProjectReturnsPathWhenPurlMatchesAndNameDiffers() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project parent = createProject("acme-app", "1.0", null);
        final Component component = createComponent(parent, "bundled-lib", "9.9", null, purl(LIB_PURL));
        final Project matched = createProject("acme-lib", "2.0", null, purl(LIB_PURL));

        final Response response = getMatchedProject(component.getUuid());

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "path": "/projects/%s"
                }
                """.formatted(matched.getUuid()));
    }

    @Test
    public void matchedProjectReturnsPathWhenPurlMatchesAndCpeIsMissing() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project parent = createProject("acme-app", "1.0", null);
        final Component component = createComponent(parent, "acme-lib", "2.0", null, purl(LIB_PURL));
        final Project matched = createProject("acme-lib", "2.0", null, purl(LIB_PURL));

        final Response response = getMatchedProject(component.getUuid());

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                        {
                          "path": "/projects/%s"
                        }
                        """.formatted(matched.getUuid()));
    }

    @Test
    public void matchedProjectNotFoundWhenPurlDiffers() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project parent = createProject("acme-app", "1.0", null);
        final Component component = createComponent(parent, "acme-lib", "2.0", null, purl(LIB_PURL));
        createProject("acme-lib", "2.0", null, purl(OTHER_PURL));

        assertNotFound(getMatchedProject(component.getUuid()));
    }

    @Test
    public void matchedProjectNotFoundWhenPurlQualifierDiffers() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project parent = createProject("acme-app", "1.0", null);
        final Component component = createComponent(parent, "acme-lib", "2.0", null, purl(LIB_PURL));
        createProject("acme-lib", "2.0", null, purl(LIB_PURL + "?type=jar"));

        assertNotFound(getMatchedProject(component.getUuid()));
    }

    @Test
    public void matchedProjectNotFoundWhenPurlIsSharedByTwoProjects() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project parent = createProject("acme-app", "1.0", null);
        final Component component = createComponent(parent, "acme-lib", "2.0", null, purl(LIB_PURL));
        createProject("acme-lib", "2.0", null, purl(LIB_PURL));
        createProject("acme-lib-copy", "2.0", null, purl(LIB_PURL));

        assertNotFound(getMatchedProject(component.getUuid()));
    }

    @Test
    public void matchedProjectNotFoundWhenCpeAndPurlPointAtDifferentProjects() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project parent = createProject("acme-app", "1.0", null);
        final Component component = createComponent(parent, "acme-lib", "2.0", COMPONENT_CPE_22, purl(LIB_PURL));
        createProject("acme-lib", "2.0", PROJECT_CPE_23);
        createProject("acme-lib-by-purl", "2.0", null, purl(LIB_PURL));

        assertNotFound(getMatchedProject(component.getUuid()));
    }

    @Test
    public void matchedProjectForbiddenWhenPurlMatchIsInaccessible() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();
        final Project parent = createProject("acme-app", "1.0", null);
        parent.addAccessTeam(super.team);
        final Component component = createComponent(parent, "bundled-lib", "9.9", null, purl(LIB_PURL));
        createProject("acme-lib", "2.0", null, purl(LIB_PURL));

        assertForbidden(getMatchedProject(component.getUuid()));
    }

    @Test
    public void matchedProjectNotFoundWhenCpeDiffersAndMatchedProjectInaccessible() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();
        final Project parent = createProject("acme-app", "1.0", null);
        parent.addAccessTeam(super.team);
        final Component component = createComponent(parent, "acme-lib", "2.0", COMPONENT_CPE_22);
        createProject("acme-lib", "2.0", OTHER_CPE_23);

        assertNotFound(getMatchedProject(component.getUuid()));
    }

    private Response getMatchedProject(UUID uuid) {
        return jersey.target(V1_COMPONENT + "/" + uuid + "/matched-project")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
    }

    private static void assertNotFound(Response response) {
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.readEntity(String.class)).isEmpty();
    }

    private void assertForbidden(Response response) {
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "%s"
                }
                """.formatted(MATCHED_PROJECT_FORBIDDEN_DETAIL));
    }

    private Project createProject(String name, String version, String cpe) {
        return createProject(name, version, cpe, null);
    }

    private Project createProject(String name, String version, String cpe, PackageURL purl) {
        final var project = new Project();
        project.setName(name);
        project.setVersion(version);
        project.setCpe(cpe);
        project.setPurl(purl);
        return qm.persist(project);
    }

    private Component createComponent(Project project, String name, String version, String cpe) {
        return createComponent(project, name, version, cpe, null);
    }

    private Component createComponent(Project project, String name, String version, String cpe, PackageURL purl) {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion(version);
        component.setCpe(cpe);
        component.setPurl(purl);
        return qm.persist(component);
    }

    private static PackageURL purl(String value) {
        try {
            return new PackageURL(value);
        } catch (MalformedPackageURLException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
