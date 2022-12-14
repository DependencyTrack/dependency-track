package org.dependencytrack;

import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.spi.TestContainer;
import org.glassfish.jersey.test.spi.TestContainerFactory;

import java.net.URI;

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

        return new DTGrizzlyWebTestContainer(baseUri, (ServletDeploymentContext) deploymentContext);
    }
}
