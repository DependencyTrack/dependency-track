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
package org.dependencytrack.resources.v2;

import com.github.packageurl.PackageURL;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.apache.http.HttpStatus;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.PackageArtifactMetadata;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Scope;
import org.dependencytrack.persistence.jdbi.PackageArtifactMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Instant;
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

public class ComponentsResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig());

    @Test
    public void createComponentTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        Project project = qm.createProject("acme", null, null, null, null, null, null, false);

        final Response response = jersey.target("/components")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "project_uuid": "%s",
                          "name": "foo",
                          "purl": "pkg:maven/org.acme/abc",
                          "hashes": {
                            "sha1": "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa",
                            "sha3_512": "301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7"
                          },
                          "supplier": {
                            "name": "supplier",
                            "contacts": [
                                {
                                  "name": "author"
                                }
                            ]
                          }
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getLocation()).isNotNull();
        assertThat(response.getLocation().getPath()).matches("/components/.+");
        assertThat(getPlainTextBody(response)).isEmpty();

        qm.getPersistenceManager().evictAll();

        final var componentsPage = qm.getComponents(project, false, false, false);
        assertThatJson(componentsPage).isEqualTo("""
                {
                  "total" : 1,
                  "objects" : [ {
                    "authors" : [ ],
                    "name" : "foo",
                    "sha1" : "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa",
                    "sha3_512" : "301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7",
                    "purl" : "pkg:maven/org.acme/abc",
                    "purlCoordinates" : "pkg:maven/org.acme/abc",
                    "project" : {
                      "name" : "acme",
                      "uuid" : "${json-unit.any-string}",
                      "isLatest" : false,
                      "active" : true
                    },
                    "uuid" : "${json-unit.any-string}",
                    "expandDependencyGraph" : false,
                    "occurrenceCount" : 0,
                    "isInternal" : false,
                    "isDirectDependency" : false
                  } ]
                }
                """);
    }

    @Test
    public void createComponentAclTest() {
        enablePortfolioAccessControl();
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        Project project = qm.createProject("acme", null, null, null, null, null, null, false);

        Response response = jersey.target("/components")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "project_uuid": "%s",
                          "name": "foo"
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(401);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                     "title" : "Unauthorized",
                     "detail" : "Not authorized to access the requested resource.",
                     "type" : "about:blank",
                     "status" : 401
                }
                """);

        project.addAccessTeam(team);
        response = jersey.target("/components")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "project_uuid": "%s",
                          "name": "foo"
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);
    }

    @Test
    public void listComponentsPaginationTest() {
        prepareComponents();
        Response response = jersey.target("/components")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "items" : [ {
                        "name": "nameA",
                        "version": "versionA",
                        "group": "groupA",
                        "cpe": "cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*",
                        "purl":"pkg:maven/groupA/nameA@versionA?foo=bar",
                        "internal": false,
                        "uuid": "${json-unit.any-string}",
                        "project": {
                            "name": "projectA",
                            "version": "1.0",
                            "uuid": "${json-unit.any-string}"
                        }
                      },
                      {
                        "name": "nameB",
                        "version": "versionB",
                        "group": "groupB",
                        "cpe": "cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*",
                        "purl":"pkg:maven/groupB/nameB@versionB?baz=qux",
                        "internal": false,
                        "scope": "OPTIONAL",
                        "uuid": "${json-unit.any-string}",
                        "project": {
                            "name": "projectB",
                            "version": "1.0",
                            "uuid": "${json-unit.any-string}"
                        }
                      }
                  ],
                  "next_page_token": "${json-unit.any-string}",
                  "total": {
                    "count": 3,
                    "type": "EXACT"
                  }
                }
                """);

        final String nextPageToken = responseJson.getString("next_page_token");
        response = jersey.target("/components")
                .queryParam("limit", 1)
                .queryParam("page_token", nextPageToken)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "items" : [ {
                        "name": "nameC",
                        "version": "versionC",
                        "group": "groupC",
                        "cpe": "cpe:2.3:a:groupC:nameC:versionC:*:*:*:*:*:*:*",
                        "purl":"pkg:maven/groupC/nameC@versionC?baz=qux",
                        "hashes": {
                            "sha1":"da39a3ee5e6b4b0d3255bfef95601890afd80709"
                        },
                        "internal": false,
                        "last_inherited_risk_score": 2.3,
                        "uuid": "${json-unit.any-string}",
                        "project": {
                            "name": "projectB",
                            "version": "1.0",
                            "uuid": "${json-unit.any-string}"
                        }
                      }
                  ],
                  "total": {
                    "count": 3,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    public void listComponentsSortingTest() {
        prepareComponents();
        final Response response = jersey.target("/components")
                .queryParam("limit", 3)
                .queryParam("sort_by", "name")
                .queryParam("sort_direction", "DESC")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "items" : [ {
                        "name": "nameC",
                        "version": "versionC",
                        "group": "groupC",
                        "cpe": "cpe:2.3:a:groupC:nameC:versionC:*:*:*:*:*:*:*",
                        "purl":"pkg:maven/groupC/nameC@versionC?baz=qux",
                        "hashes": {
                            "sha1":"da39a3ee5e6b4b0d3255bfef95601890afd80709"
                        },
                        "internal": false,
                        "last_inherited_risk_score": 2.3,
                        "uuid": "${json-unit.any-string}",
                        "project": {
                            "name": "projectB",
                            "version": "1.0",
                            "uuid": "${json-unit.any-string}"
                        }
                      },
                      {
                        "name": "nameB",
                        "version": "versionB",
                        "group": "groupB",
                        "cpe": "cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*",
                        "purl":"pkg:maven/groupB/nameB@versionB?baz=qux",
                        "internal": false,
                        "scope": "OPTIONAL",
                        "uuid": "${json-unit.any-string}",
                        "project": {
                            "name": "projectB",
                            "version": "1.0",
                            "uuid": "${json-unit.any-string}"
                        }
                      },
                      {
                        "name": "nameA",
                        "version": "versionA",
                        "group": "groupA",
                        "cpe": "cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*",
                        "purl":"pkg:maven/groupA/nameA@versionA?foo=bar",
                        "internal": false,
                        "uuid": "${json-unit.any-string}",
                        "project": {
                            "name": "projectA",
                            "version": "1.0",
                            "uuid": "${json-unit.any-string}"
                        }
                      }
                  ],
                  "total": {
                    "count": 3,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    public void listComponentsWithCoordinatesTest() {
        prepareComponents();
        Response response = jersey.target("/components")
                .queryParam("group_contains", "B")
                .queryParam("name_contains", "B")
                .queryParam("version_contains", "versionB")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "items" : [ {
                        "name": "nameB",
                        "version": "versionB",
                        "group": "groupB",
                        "cpe": "cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*",
                        "purl":"pkg:maven/groupB/nameB@versionB?baz=qux",
                        "internal": false,
                        "scope": "OPTIONAL",
                        "uuid": "${json-unit.any-string}",
                        "project": {
                            "name": "projectB",
                            "version": "1.0",
                            "uuid": "${json-unit.any-string}"
                        }
                      }
                  ],
                  "total": {
                    "count": 1,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    public void listComponentsWithPurlTest() {
        prepareComponents();
        Response response = jersey.target("/components")
                .queryParam("purl_prefix", "pkg:maven/groupB/nameB@versionB")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "items" : [ {
                        "name": "nameB",
                        "version": "versionB",
                        "group": "groupB",
                        "cpe": "cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*",
                        "purl":"pkg:maven/groupB/nameB@versionB?baz=qux",
                        "internal": false,
                        "scope": "OPTIONAL",
                        "uuid": "${json-unit.any-string}",
                        "project": {
                            "name": "projectB",
                            "version": "1.0",
                            "uuid": "${json-unit.any-string}"
                        }
                      }
                  ],
                  "total": {
                    "count": 1,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    public void listComponentsWithInvalidCpeTest() {
        prepareComponents();
        Response response = jersey.target("/components")
                .queryParam("cpe", "nameB")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_BAD_REQUEST);
        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson.toString()).contains("Invalid CPE: nameB");
    }

    @Test
    public void listComponentsWithCpeTest() {
        prepareComponents();
        Response response = jersey.target("/components")
                .queryParam("cpe", "cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "items" : [ {
                        "name": "nameB",
                        "version": "versionB",
                        "group": "groupB",
                        "cpe": "cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*",
                        "purl":"pkg:maven/groupB/nameB@versionB?baz=qux",
                        "internal": false,
                        "scope": "OPTIONAL",
                        "uuid": "${json-unit.any-string}",
                        "project": {
                            "name": "projectB",
                            "version": "1.0",
                            "uuid": "${json-unit.any-string}"
                        }
                      }
                  ],
                  "total": {
                    "count": 1,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    public void listComponentsAclTest() {
        enablePortfolioAccessControl();
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        prepareComponents();
        Response response = jersey.target("/components")
                .queryParam("name_contains", "name")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "items" : [ {
                        "name": "nameA",
                        "version": "versionA",
                        "group": "groupA",
                        "cpe": "cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*",
                        "purl":"pkg:maven/groupA/nameA@versionA?foo=bar",
                        "internal": false,
                        "uuid": "${json-unit.any-string}",
                        "project": {
                            "name": "projectA",
                            "version": "1.0",
                            "uuid": "${json-unit.any-string}"
                        }
                      }
                  ],
                  "total": {
                    "count": 1,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    public void listComponentByHashTest() {
        prepareComponents();
        Response response = jersey.target("/components")
                .queryParam("hash_type", "SHA1")
                .queryParam("hash", "da39a3ee5e6b4b0d3255bfef95601890afd80709")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "items" : [ {
                        "name": "nameC",
                        "version": "versionC",
                        "group": "groupC",
                        "cpe": "cpe:2.3:a:groupC:nameC:versionC:*:*:*:*:*:*:*",
                        "purl":"pkg:maven/groupC/nameC@versionC?baz=qux",
                        "hashes": {
                            "sha1":"da39a3ee5e6b4b0d3255bfef95601890afd80709"
                        },
                        "internal": false,
                        "last_inherited_risk_score": 2.3,
                        "uuid": "${json-unit.any-string}",
                        "project": {
                            "name": "projectB",
                            "version": "1.0",
                            "uuid": "${json-unit.any-string}"
                        }
                      }
                  ],
                  "total": {
                    "count": 1,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    public void listComponentsWithInvalidProjectStateTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Response response = jersey
                .target("/components")
                .queryParam("project_state", "invalid")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_BAD_REQUEST);
        assertThatJson(parseJsonObject(response).toString()).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "The request could not be processed because it failed validation.",
                  "errors": [
                    {
                      "path": "project_state",
                      "message": "Invalid parameter value."
                    }
                  ]
                }
                """);
    }

    @Test
    public void listComponentsByProjectStateAndLatestVersionTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var activeLatestProject = new Project();
        activeLatestProject.setName("activeLatestProject");
        activeLatestProject.setIsLatest(true);
        qm.persist(activeLatestProject);
        final var activeLatest = new Component();
        activeLatest.setProject(activeLatestProject);
        activeLatest.setName("activeLatest");
        qm.persist(activeLatest);

        final var activeNotLatestProject = new Project();
        activeNotLatestProject.setName("activeNotLatestProject");
        qm.persist(activeNotLatestProject);
        final var activeNotLatest = new Component();
        activeNotLatest.setProject(activeNotLatestProject);
        activeNotLatest.setName("activeNotLatest");
        qm.persist(activeNotLatest);

        final var inactiveLatestProject = new Project();
        inactiveLatestProject.setName("inactiveLatestProject");
        inactiveLatestProject.setIsLatest(true);
        inactiveLatestProject.setInactiveSince(new java.util.Date());
        qm.persist(inactiveLatestProject);
        final var inactiveLatest = new Component();
        inactiveLatest.setProject(inactiveLatestProject);
        inactiveLatest.setName("inactiveLatest");
        qm.persist(inactiveLatest);

        final var inactiveNotLatestProject = new Project();
        inactiveNotLatestProject.setName("inactiveNotLatestProject");
        inactiveNotLatestProject.setInactiveSince(new java.util.Date());
        qm.persist(inactiveNotLatestProject);
        final var inactiveNotLatest = new Component();
        inactiveNotLatest.setProject(inactiveNotLatestProject);
        inactiveNotLatest.setName("inactiveNotLatest");
        qm.persist(inactiveNotLatest);

        Response response = jersey
                .target("/components")
                .queryParam("project_state", "ACTIVE")
                .queryParam("limit", 10)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(parseJsonObject(response).toString())
                .inPath("$.items[*].name")
                .isArray()
                .containsExactlyInAnyOrder("activeLatest", "activeNotLatest");

        response = jersey
                .target("/components")
                .queryParam("project_state", "INACTIVE")
                .queryParam("limit", 10)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(parseJsonObject(response).toString())
                .inPath("$.items[*].name")
                .isArray()
                .containsExactlyInAnyOrder("inactiveLatest", "inactiveNotLatest");

        response = jersey
                .target("/components")
                .queryParam("project_latest_version", "true")
                .queryParam("limit", 10)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(parseJsonObject(response).toString())
                .inPath("$.items[*].name")
                .isArray()
                .containsExactlyInAnyOrder("activeLatest", "inactiveLatest");

        response = jersey
                .target("/components")
                .queryParam("project_latest_version", "false")
                .queryParam("limit", 10)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(parseJsonObject(response).toString())
                .inPath("$.items[*].name")
                .isArray()
                .containsExactlyInAnyOrder("activeNotLatest", "inactiveNotLatest");

        response = jersey
                .target("/components")
                .queryParam("project_state", "ACTIVE")
                .queryParam("project_latest_version", "false")
                .queryParam("limit", 10)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(parseJsonObject(response).toString())
                .inPath("$.items[*].name")
                .isArray()
                .containsExactly("activeNotLatest");

        response = jersey
                .target("/components")
                .queryParam("limit", 10)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(parseJsonObject(response).toString())
                .inPath("$.items[*].name")
                .isArray()
                .containsExactlyInAnyOrder("activeLatest", "activeNotLatest", "inactiveLatest", "inactiveNotLatest");
    }

    @Test
    public void listComponentsWithPackageMetadataTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("test", null, "1.0", null, null, null, null, false);
        final var component = new Component();
        component.setProject(project);
        component.setName("comp");
        component.setPurl(new PackageURL("maven", "test", "comp", "1.0", null, null));
        qm.createComponent(component, false);

        final Instant resolvedAt = Instant.ofEpochMilli(1_700_000_000_000L);
        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(
                        new PackageURL("maven", "test", "comp", null, null, null),
                        "2.0",
                        null,
                        resolvedAt,
                        null,
                        null))));

        final Response response = jersey.target("/components")
                .queryParam("expand", "package_metadata")
                .queryParam("limit", 10)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.items[0].package_metadata")
                .isEqualTo(/* language=JSON */ """
                        {
                          "latest_version": "2.0",
                          "resolved_at": 1700000000000
                        }
                        """);
    }

    @Test
    public void listComponentsWithArtifactMetadataTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("test", null, "1.0", null, null, null, null, false);
        final var component = new Component();
        component.setProject(project);
        component.setName("comp");
        component.setPurl(new PackageURL("maven", "test", "comp", "1.0", null, null));
        qm.createComponent(component, false);

        final Instant resolvedAt = Instant.ofEpochMilli(1_700_000_000_000L);
        final Instant publishedAt = Instant.ofEpochMilli(1_600_000_000_000L);
        final var packagePurl = new PackageURL("maven", "test", "comp", null, null, null);
        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(packagePurl, null, null, resolvedAt, null, null))));
        useJdbiHandle(handle -> new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                new PackageArtifactMetadata(
                        new PackageURL("maven", "test", "comp", "1.0", null, null),
                        packagePurl,
                        null,
                        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                        null,
                        publishedAt,
                        null,
                        "central",
                        resolvedAt))));

        final Response response = jersey
                .target("/components")
                .queryParam("expand", "package_artifact_metadata")
                .queryParam("limit", 10)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.items[0].package_artifact_metadata")
                .isEqualTo(/* language=JSON */ """
                        {
                          "hashes": {
                            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                          },
                          "published_at": 1600000000000,
                          "resolved_from": "central",
                          "resolved_at": 1700000000000
                        }
                        """);
    }

    @Test
    public void listComponentsFilterByPackageArtifactPublishedAtTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("test", null, "1.0", null, null, null, null, false);
        final long t0 = 1_500_000_000_000L;
        final long t1 = 1_600_000_000_000L;
        final long t2 = 1_700_000_000_000L;

        final var c0 = createComponentWithPublishedAt(project, "c0", Instant.ofEpochMilli(t0));
        final var c1 = createComponentWithPublishedAt(project, "c1", Instant.ofEpochMilli(t1));
        final var c2 = createComponentWithPublishedAt(project, "c2", Instant.ofEpochMilli(t2));
        assertThat(c0).isNotNull();
        assertThat(c1).isNotNull();
        assertThat(c2).isNotNull();

        final Response from = jersey
                .target("/components")
                .queryParam("package_artifact_published_since", t1)
                .queryParam("limit", 10)
                .request().header(X_API_KEY, apiKey).get();
        assertThat(from.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(from))
                .inPath("$.items[*].name")
                .isArray()
                .containsExactlyInAnyOrder("c1", "c2");

        final Response to = jersey
                .target("/components")
                .queryParam("package_artifact_published_before", t2)
                .queryParam("limit", 10)
                .request().header(X_API_KEY, apiKey).get();
        assertThat(to.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(to))
                .inPath("$.items[*].name")
                .isArray()
                .containsExactlyInAnyOrder("c0", "c1");

        final Response range = jersey
                .target("/components")
                .queryParam("package_artifact_published_since", t1)
                .queryParam("package_artifact_published_before", t2)
                .queryParam("limit", 10)
                .request().header(X_API_KEY, apiKey).get();
        assertThat(range.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(range))
                .inPath("$.items[*].name")
                .isArray()
                .containsExactly("c1");
    }

    private Component createComponentWithPublishedAt(final Project project, final String name, final Instant publishedAt) throws Exception {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setPurl(new PackageURL("maven", "test", name, "1.0", null, null));
        qm.createComponent(component, false);

        final var packagePurl = new PackageURL("maven", "test", name, null, null, null);
        final Instant resolvedAt = Instant.ofEpochMilli(1_700_000_000_000L);
        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(packagePurl, null, null, resolvedAt, null, null))));
        useJdbiHandle(handle -> new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                new PackageArtifactMetadata(
                        new PackageURL("maven", "test", name, "1.0", null, null),
                        packagePurl,
                        null,
                        null,
                        null,
                        null,
                        publishedAt,
                        null,
                        "central",
                        resolvedAt))));
        return component;
    }

    private void prepareComponents() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, null, false);
        projectA.addAccessTeam(team);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("groupA");
        componentA.setName("nameA");
        componentA.setVersion("versionA");
        componentA.setCpe("cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*");
        componentA.setPurl("pkg:maven/groupA/nameA@versionA?foo=bar");
        qm.createComponent(componentA, false);
        projectA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentA).toJSON()));

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, null, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("groupB");
        componentB.setName("nameB");
        componentB.setVersion("versionB");
        componentB.setScope(Scope.OPTIONAL);
        componentB.setCpe("cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*");
        componentB.setPurl("pkg:maven/groupB/nameB@versionB?baz=qux");
        qm.createComponent(componentB, false);

        var componentC = new Component();
        componentC.setProject(projectB);
        componentC.setGroup("groupC");
        componentC.setName("nameC");
        componentC.setVersion("versionC");
        componentC.setCpe("cpe:2.3:a:groupC:nameC:versionC:*:*:*:*:*:*:*");
        componentC.setPurl("pkg:maven/groupC/nameC@versionC?baz=qux");
        componentC.setSha1("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        componentC.setLastInheritedRiskScore(2.3);
        qm.createComponent(componentC, false);
    }
}
