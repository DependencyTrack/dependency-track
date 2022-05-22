package org.dependencytrack.tasks;

import alpine.server.persistence.PersistenceManagerFactory;
import org.dependencytrack.event.MetricsUpdateEvent;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.glassfish.jersey.test.spi.TestContainerFactory;
import org.junit.Ignore;
import org.junit.Test;

/**
 * FIXME: Remove before creating a PR
 */
@Ignore
public class NewMetricsUpdateTaskBenchmarkTest extends JerseyTest {

    @Override
    protected TestContainerFactory getTestContainerFactory() {
        return new GrizzlyWebTestContainerFactory();
    }

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer())
                .addListener(PersistenceManagerFactory.class).build();
    }

    @Test
    public void testNewImpl() {
        new NewMetricsUpdateTask().inform(new MetricsUpdateEvent(MetricsUpdateEvent.Type.PORTFOLIO));
    }

    @Test
    public void testCurrentImpl() {
        new MetricsUpdateTask().inform(new MetricsUpdateEvent(MetricsUpdateEvent.Type.PORTFOLIO));
    }

    @Test
    public void testVulnNewImpl() {
        new NewMetricsUpdateTask().inform(new MetricsUpdateEvent(MetricsUpdateEvent.Type.VULNERABILITY));
    }

    @Test
    public void testVulnCurrentImpl() {
        new MetricsUpdateTask().inform(new MetricsUpdateEvent(MetricsUpdateEvent.Type.VULNERABILITY));
    }

}
