package org.dependencytrack.resources.v1;

import org.dependencytrack.ResourceTest;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Test;

import javax.ws.rs.core.Response;

import static org.assertj.core.api.Assertions.assertThat;

public class OidcResourceUnauthenticatedTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(new ResourceConfig(OidcResource.class))).build();
    }

    @Test
    public void isAvailableShouldReturnFalseWhenOidcIsNotAvailable() {
        final Response response = target(V1_OIDC + "/available")
                .request().get();

        assertThat(getPlainTextBody(response)).isEqualTo("false");
    }

}