package org.dependencytrack.resources.v1;

import alpine.filters.AuthenticationFilter;
import org.dependencytrack.ResourceTest;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;

public class OidcResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(OidcResource.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

}