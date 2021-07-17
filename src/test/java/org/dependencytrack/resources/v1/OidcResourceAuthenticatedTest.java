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
 */
package org.dependencytrack.resources.v1;

import alpine.filters.ApiFilter;
import alpine.filters.AuthenticationFilter;
import alpine.model.MappedOidcGroup;
import alpine.model.OidcGroup;
import alpine.model.Team;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.resources.v1.vo.MappedOidcGroupRequest;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Test;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class OidcResourceAuthenticatedTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(new ResourceConfig(OidcResource.class)
                .register(ApiFilter.class)
                .register(AuthenticationFilter.class))).build();
    }

    @Test
    public void retrieveGroupsShouldReturnListOfGroups() {
        final OidcGroup oidcGroup = new OidcGroup();
        oidcGroup.setName("groupName");
        qm.persist(oidcGroup);

        final Response response = target(V1_OIDC + "/group")
                .request().header(X_API_KEY, apiKey).get();

        assertThat(response.getStatus()).isEqualTo(200);

        final JsonArray jsonGroups = parseJsonArray(response);
        assertThat(jsonGroups).hasSize(1);
        assertThat(jsonGroups.getJsonObject(0).getString("name")).isEqualTo("groupName");
    }

    @Test
    public void retrieveGroupsShouldReturnEmptyListWhenNoGroupsWhereFound() {
        final Response response = target(V1_OIDC + "/group")
                .request().header(X_API_KEY, apiKey).get();

        assertThat(response.getStatus()).isEqualTo(200);

        final JsonArray jsonGroups = parseJsonArray(response);
        assertThat(jsonGroups).isEmpty();
    }

    @Test
    public void createGroupShouldReturnCreatedGroup() {
        final OidcGroup oidcGroup = new OidcGroup();
        oidcGroup.setName("groupName");

        final Response response = target(V1_OIDC + "/group")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(oidcGroup, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObject group = parseJsonObject(response);
        assertThat(group.getJsonObject("id")).isNull();
        assertThat(group.getString("uuid")).isNotEmpty();
        assertThat(group.getString("name")).isEqualTo("groupName");
    }

    @Test
    public void createGroupShouldIndicateConflictWhenGroupAlreadyExists() {
        qm.createOidcGroup("groupName");

        final OidcGroup oidcGroup = new OidcGroup();
        oidcGroup.setName("groupName");

        final Response response = target(V1_OIDC + "/group")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(oidcGroup, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(409);
    }

    @Test
    public void createGroupShouldIndicateBadRequestWhenRequestIsInvalid() {
        final OidcGroup oidcGroup = new OidcGroup();
        oidcGroup.setName(" ");

        final Response response = target(V1_OIDC + "/group")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(oidcGroup, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    public void updateGroupShouldUpdateAndReturnGroup() {
        final OidcGroup existingGroup = qm.createOidcGroup("groupName");

        final OidcGroup jsonGroup = new OidcGroup();
        jsonGroup.setUuid(existingGroup.getUuid());
        jsonGroup.setName("newGroupName");

        final Response response = target(V1_OIDC + "/group").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonGroup, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(200);

        final JsonObject groupObject = parseJsonObject(response);
        assertThat(groupObject.getString("uuid")).isEqualTo(jsonGroup.getUuid().toString());
        assertThat(groupObject.getString("name")).isEqualTo("newGroupName");
    }

    @Test
    public void updateGroupShouldIndicateBadRequestWhenRequestBodyIsInvalid() {
        final OidcGroup jsonGroup = new OidcGroup();

        final Response response = target(V1_OIDC + "/group").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonGroup, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    public void updateGroupShouldIndicateNotFoundWhenGroupDoesNotExist() {
        final OidcGroup jsonGroup = new OidcGroup();
        jsonGroup.setUuid(UUID.randomUUID());
        jsonGroup.setName("groupName");

        final Response response = target(V1_OIDC + "/group").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonGroup, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void deleteGroupShouldDeleteGroupAndIndicateNoContent() {
        final OidcGroup existingOidcGroup = qm.createOidcGroup("groupName");

        final Response response = target(V1_OIDC + "/group/" + existingOidcGroup.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(qm.getObjectByUuid(OidcGroup.class, existingOidcGroup.getUuid())).isNull();
    }

    @Test
    public void deleteGroupShouldIndicateNotFoundWhenGroupDoesNotExist() {
        final Response response = target(V1_OIDC + "/group/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void retrieveTeamsMappedToGroupShouldReturnTeamsMappedToSpecifiedGroup() {
        final OidcGroup oidcGroup = qm.createOidcGroup("groupName");
        final Team team = qm.createTeam("teamName", false);
        qm.createMappedOidcGroup(team, oidcGroup);

        final Response response = target(V1_OIDC + "/group/" + oidcGroup.getUuid() + "/team")
                .request().header(X_API_KEY, apiKey).get();

        assertThat(response.getStatus()).isEqualTo(200);

        final JsonArray teamsArray = parseJsonArray(response);
        assertThat(teamsArray).hasSize(1);
        assertThat(teamsArray.getJsonObject(0).getString("name")).isEqualTo("teamName");
    }

    @Test
    public void retrieveTeamsMappedToGroupShouldIndicateNotFoundWhenGroupDoesNotExit() {
        final Response response = target(V1_OIDC + "/group/" + UUID.randomUUID() + "/team")
                .request().header(X_API_KEY, apiKey).get();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void addMappingShouldIndicateBadRequestWhenRequestIsInvalid() {
        final MappedOidcGroupRequest request = new MappedOidcGroupRequest("not-a-uuid", "not-a-uuid");

        final Response response = target(V1_OIDC + "/mapping")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    public void addMappingShouldIndicateNotFoundWhenTeamDoesNotExist() {
        final OidcGroup group = qm.createOidcGroup("groupName");

        final MappedOidcGroupRequest request = new MappedOidcGroupRequest(UUID.randomUUID().toString(), group.getUuid().toString());

        final Response response = target(V1_OIDC + "/mapping")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void addMappingShouldIndicateNotFoundWhenGroupDoesNotExist() {
        final Team team = qm.createTeam("teamName", false);

        final MappedOidcGroupRequest request = new MappedOidcGroupRequest(team.getUuid().toString(), UUID.randomUUID().toString());

        final Response response = target(V1_OIDC + "/mapping")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void addMappingShouldIndicateConflictWhenMappingAlreadyExists() {
        final Team team = qm.createTeam("teamName", false);
        final OidcGroup group = qm.createOidcGroup("groupName");
        qm.createMappedOidcGroup(team, group);

        final MappedOidcGroupRequest request = new MappedOidcGroupRequest(team.getUuid().toString(), group.getUuid().toString());

        final Response response = target(V1_OIDC + "/mapping")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(409);
    }

    @Test
    public void addMappingShouldReturnCreatedMapping() {
        final Team team = qm.createTeam("teamName", false);
        final OidcGroup group = qm.createOidcGroup("groupName");

        final MappedOidcGroupRequest request = new MappedOidcGroupRequest(team.getUuid().toString(), group.getUuid().toString());

        final Response response = target(V1_OIDC + "/mapping")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(200);

        final JsonObject mapping = parseJsonObject(response);
        assertThat(mapping.getJsonObject("id")).isNull();
        assertThat(mapping.getString("uuid")).isNotEmpty();
        assertThat(mapping.getJsonObject("team")).isNull();
        assertThat(mapping.getJsonObject("group")).isNotNull();
    }

    @Test
    public void deleteMappingByUuidShouldDeleteMappingAndIndicateNoContent() {
        final Team team = qm.createTeam("teamName", false);
        final OidcGroup group = qm.createOidcGroup("groupName");
        final MappedOidcGroup mapping = qm.createMappedOidcGroup(team, group);

        final Response response = target(V1_OIDC + "/mapping/" + mapping.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(qm.getObjectByUuid(MappedOidcGroup.class, mapping.getUuid())).isNull();
    }

    @Test
    public void deleteMappingByUuidShouldIndicateNotFoundWhenMappingDoesNotExist() {
        final Response response = target(V1_OIDC + "/mapping/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void deleteMappingShouldDeleteMappingAndIndicateNoContent() {
        final OidcGroup oidcGroup = qm.createOidcGroup("groupName");
        final Team team = qm.createTeam("teamName", false);
        final MappedOidcGroup mapping = qm.createMappedOidcGroup(team, oidcGroup);

        final Response response = target(V1_OIDC + "/group/" + oidcGroup.getUuid() + "/team/" + team.getUuid() + "/mapping").request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(qm.getObjectByUuid(MappedOidcGroup.class, mapping.getUuid())).isNull();
    }

    @Test
    public void deleteMappingShouldIndicateNotFoundWhenTeamDoesNotExist() {
        final OidcGroup oidcGroup = qm.createOidcGroup("groupName");

        final Response response = target(V1_OIDC + "/group/" + oidcGroup.getUuid() + "/team/" + UUID.randomUUID() + "/mapping").request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void deleteMappingShouldIndicateNotFoundWhenGroupDoesNotExist() {
        final Team team = qm.createTeam("teamName", false);

        final Response response = target(V1_OIDC + "/group/" + UUID.randomUUID() + "/team/" + team.getUuid() + "/mapping").request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void deleteMappingShouldIndicateNotFoundWhenMappingDoesNotExist() {
        final OidcGroup oidcGroup = qm.createOidcGroup("groupName");
        final Team team = qm.createTeam("teamName", false);

        final Response response = target(V1_OIDC + "/group/" + oidcGroup.getUuid() + "/team/" + team.getUuid() + "/mapping").request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
    }

}
