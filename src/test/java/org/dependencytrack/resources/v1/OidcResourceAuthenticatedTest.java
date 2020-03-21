package org.dependencytrack.resources.v1;

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
                .register(AuthenticationFilter.class))).build();
    }

    @Test
    public void retrieveOidcGroupsShouldReturnListOfGroups() {
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
    public void retrieveOidcGroupsShouldReturnEmptyListWhenNoGroupsWhereFound() {
        final Response response = target(V1_OIDC + "/group")
                .request().header(X_API_KEY, apiKey).get();

        assertThat(response.getStatus()).isEqualTo(200);

        final JsonArray jsonGroups = parseJsonArray(response);
        assertThat(jsonGroups).isEmpty();
    }

    @Test
    public void createOidcGroupShouldReturnCreatedGroup() {
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
    public void createOidcGroupShouldIndicateConflictWhenGroupAlreadyExists() {
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
    public void createOidcGroupShouldIndicateBadRequestWhenRequestIsInvalid() {
        final OidcGroup oidcGroup = new OidcGroup();
        oidcGroup.setName(" ");

        final Response response = target(V1_OIDC + "/group")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(oidcGroup, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    public void deleteOidcGroupShouldDeleteGroupAndIndicateNoContent() {
        final OidcGroup existingOidcGroup = qm.createOidcGroup("groupName");

        final Response response = target(V1_OIDC + "/group/" + existingOidcGroup.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(qm.getObjectByUuid(OidcGroup.class, existingOidcGroup.getUuid())).isNull();
    }

    @Test
    public void deleteOidcGroupShouldIndicateNotFoundWhenGroupDoesNotExist() {
        final Response response = target(V1_OIDC + "/group/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void retrieveOidcGroupMappingShouldReturnAllGroupMappingsForATeam() {
        final Team team = qm.createTeam("teamName", false);
        final OidcGroup group = qm.createOidcGroup("groupName");
        qm.createMappedOidcGroup(team, group);

        final Response response = target(V1_OIDC + "/team/" + team.getUuid())
                .request().header(X_API_KEY, apiKey).get();

        assertThat(response.getStatus()).isEqualTo(200);

        final JsonArray mappingsArray = parseJsonArray(response);
        assertThat(mappingsArray).hasSize(1);
        assertThat(mappingsArray.getJsonObject(0).getJsonObject("id")).isNull();
        assertThat(mappingsArray.getJsonObject(0).getString("uuid")).isNotEmpty();
        assertThat(mappingsArray.getJsonObject(0).getJsonObject("team")).isNull();
        assertThat(mappingsArray.getJsonObject(0).getJsonObject("group")).isNotNull();
    }

    @Test
    public void retrieveOidcGroupMappingsShouldIndicateNotFoundWhenTeamDoesNotExist() {
        final Response response = target(V1_OIDC + "/team/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void addOidcGroupMappingShouldIndicateBadRequestWhenRequestIsInvalid() {
        final MappedOidcGroupRequest request = new MappedOidcGroupRequest("not-a-uuid", "not-a-uuid");

        final Response response = target(V1_OIDC + "/mapping")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    public void addOidcGroupMappingShouldIndicateNotFoundWhenTeamDoesNotExist() {
        final OidcGroup group = qm.createOidcGroup("groupName");

        final MappedOidcGroupRequest request = new MappedOidcGroupRequest(UUID.randomUUID().toString(), group.getUuid().toString());

        final Response response = target(V1_OIDC + "/mapping")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void addOidcGroupMappingShouldIndicateNotFoundWhenGroupDoesNotExist() {
        final Team team = qm.createTeam("teamName", false);

        final MappedOidcGroupRequest request = new MappedOidcGroupRequest(team.getUuid().toString(), UUID.randomUUID().toString());

        final Response response = target(V1_OIDC + "/mapping")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void addOidcGroupMappingShouldIndicateConflictWhenMappingAlreadyExists() {
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
    public void addOidcGroupMappingShouldReturnCreatedMapping() {
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
    public void deleteOidcGroupMappingShouldDeleteMappingAndIndicateNoContent() {
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
    public void deleteOidcGroupMappingShouldIndicateNotFoundWhenMappingDoesNotExist() {
        final Response response = target(V1_OIDC + "/mapping/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
    }

}
