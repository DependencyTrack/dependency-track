package org.dependencytrack;

import alpine.Config;
import org.dependencytrack.persistence.QueryManager;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.glassfish.jersey.test.spi.TestContainerFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;

import static org.dependencytrack.PersistenceCapableTest.dbReset;

public abstract class TaskTest extends JerseyTest {

    protected QueryManager qm;

    @BeforeClass
    public static void init() {
        Config.enableUnitTests();
    }

    @Override
    protected TestContainerFactory getTestContainerFactory() {
        return new GrizzlyWebTestContainerFactory();
    }

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer()).build();
    }

    @Before
    public void setUp() throws Exception {
        dbReset();
        qm = new QueryManager();
    }

    @After
    public void after() throws Exception {
        dbReset();
        qm.close();
    }

}
