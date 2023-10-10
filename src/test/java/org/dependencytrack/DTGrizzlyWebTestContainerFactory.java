package org.dependencytrack;

import org.apache.commons.lang3.reflect.FieldUtils;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.glassfish.jersey.test.spi.TestContainer;
import org.glassfish.jersey.test.spi.TestContainerFactory;

import java.net.URI;

import static org.junit.Assert.fail;

/**
 * Custom factory needed to instantiate a TestContainer allowing body payload for DELETE method.
 *
 * @See org.dependencytrack.DTGrizzlyWebTestContainer
 */
public class DTGrizzlyWebTestContainerFactory implements TestContainerFactory {
    @Override
    public TestContainer create(URI baseUri, DeploymentContext deploymentContext) {
        if (!(deploymentContext instanceof ServletDeploymentContext)) {
            throw new IllegalArgumentException("The deployment context must be an instance of ServletDeploymentContext.");
        }

        final TestContainer testContainer = new GrizzlyWebTestContainerFactory().create(baseUri, deploymentContext);
        try {
            HttpServer server = (HttpServer) FieldUtils.readDeclaredField(testContainer, "server", true);
            server.getServerConfiguration().setAllowPayloadForUndefinedHttpMethods(true);
        } catch (IllegalAccessException e) {
            fail(e.getMessage());
        }
        return testContainer;
    }
}
