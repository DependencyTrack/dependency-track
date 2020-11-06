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
package org.dependencytrack;

import alpine.Config;
import alpine.auth.JsonWebToken;
import alpine.auth.JwtAuthenticationService;
import alpine.auth.PasswordService;
import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.model.Team;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.QueryManager;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.glassfish.jersey.test.spi.TestContainerFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.ws.rs.core.Response;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import static org.dependencytrack.PersistenceCapableTest.dbReset;

public abstract class ResourceTest extends JerseyTest {

    protected final String V1_ANALYSIS = "/v1/analysis";
    protected final String V1_BOM = "/v1/bom";
    protected final String V1_CALCULATOR = "/v1/calculator";
    protected final String V1_COMPONENT = "/v1/component";
    protected final String V1_CONFIG_PROPERTY = "/v1/configProperty";
    protected final String V1_CWE = "/v1/cwe";
    protected final String V1_DEPENDENCY = "/v1/dependency";
    protected final String V1_FINDING = "/v1/finding";
    protected final String V1_LDAP = "/v1/ldap";
    protected final String V1_LICENSE = "/v1/license";
    protected final String V1_METRICS = "/v1/metrics";
    protected final String V1_NOTIFICATION_PUBLISHER = "/v1/notification/publisher";
    protected final String V1_NOTIFICATION_RULE = "/v1/notification/rule";
    protected final String V1_OIDC = "/v1/oidc";
    protected final String V1_PERMISSION = "/v1/permission";
    protected final String V1_POLICY = "/v1/policy";
    protected final String V1_PROJECT = "/v1/project";
    protected final String V1_REPOSITORY = "/v1/repository";
    protected final String V1_SCAN = "/v1/scan";
    protected final String V1_SEARCH = "/v1/search";
    protected final String V1_TEAM = "/v1/team";
    protected final String V1_USER = "/v1/user";
    protected final String V1_VULNERABILITY = "/v1/vulnerability";
    protected final String ORDER_BY = "orderBy";
    protected final String SORT = "sort";
    protected final String SORT_ASC = "asc";
    protected final String SORT_DESC = "desc";
    protected final String FILTER = "filter";
    protected final String PAGE = "page";
    protected final String SIZE = "size";
    protected final String TOTAL_COUNT_HEADER = "X-Total-Count";
    protected final String X_API_KEY = "X-Api-Key";

    protected QueryManager qm;
    protected ManagedUser testUser;
    protected String jwt;
    protected Team team;
    protected String apiKey;

    @BeforeClass
    public static void init() {
        Config.enableUnitTests();
    }

    @Before
    public void before() throws Exception {
        dbReset();
        // Add a test user and team with API key. Optional if this is used, but its available to all tests.
        this.qm = new QueryManager();
        testUser = qm.createManagedUser("testuser", String.valueOf(PasswordService.createHash("testuser".toCharArray())));
        this.jwt = new JsonWebToken().createToken(testUser);
        team = qm.createTeam("Test Users", true);
        qm.addUserToTeam(testUser, team);
        this.apiKey = team.getApiKeys().get(0).getKey();
    }

    @After
    public void after() throws Exception {
        dbReset();
        this.qm.close();
    }

    @Override
    protected TestContainerFactory getTestContainerFactory() {
        return new GrizzlyWebTestContainerFactory();
    }

    public void initializeWithPermissions(Permissions... permissions) {
        List<Permission> permissionList = new ArrayList<>();
        for (Permissions permission: permissions) {
            permissionList.add(qm.createPermission(permission.name(), null));
        }
        testUser.setPermissions(permissionList);
        team.setPermissions(permissionList);
        qm.persist(team);
        testUser = qm.persist(testUser);
    }

    protected String getPlainTextBody(Response response) {
        return response.readEntity(String.class);
    }

    protected JsonObject parseJsonObject(Response response) {
        StringReader stringReader = new StringReader(response.readEntity(String.class));
        try (JsonReader jsonReader = Json.createReader(stringReader)) {
            return jsonReader.readObject();
        }
    }

    protected JsonArray parseJsonArray(Response response) {
        StringReader stringReader = new StringReader(response.readEntity(String.class));
        try (JsonReader jsonReader = Json.createReader(stringReader)) {
            return jsonReader.readArray();
        }
    }
}
