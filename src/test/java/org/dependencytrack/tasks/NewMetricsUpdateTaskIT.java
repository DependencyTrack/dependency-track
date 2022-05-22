package org.dependencytrack.tasks;

import alpine.persistence.JdoProperties;
import alpine.server.persistence.PersistenceManagerFactory;
import org.datanucleus.PropertyNames;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.dependencytrack.event.MetricsUpdateEvent;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.HostPortWaitStrategy;
import org.testcontainers.utility.DockerImageName;

import javax.jdo.JDOHelper;
import java.util.List;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

public class NewMetricsUpdateTaskIT {

    @Ignore // There is no image for arm64
    public static class MssqlTest {

        @Rule
        @SuppressWarnings("rawtypes")
        public final GenericContainer<?> container = new GenericContainer(DockerImageName.parse("mcr.microsoft.com/mssql/server:2019-latest"))
                .withEnv("SA_PASSWORD", "DTrack1234!")
                .withEnv("ACCEPT_EULA", "y")
                .withExposedPorts(1433)
                .waitingFor(new HostPortWaitStrategy());

        @Before
        public void setUp() throws Exception {
            // We need to create the database manually because the container won't do it automatically.
            container.execInContainer("/opt/mssql-tools/bin/sqlcmd", "-S", "localhost", "-U", "sa", "-P", "DTrack1234!", "-Q", "CREATE DATABASE dtrack");

            final Properties jdoProps = JdoProperties.get();
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_URL, "jdbc:sqlserver://localhost:" + container.getFirstMappedPort() +
                    ";databaseName=dtrack;sendStringParametersAsUnicode=false;trustServerCertificate=true");
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_DRIVER_NAME, com.microsoft.sqlserver.jdbc.SQLServerDriver.class.getName());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_USER_NAME, "sa");
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_PASSWORD, "DTrack1234!");

            final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(jdoProps, "Alpine");
            PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);

            populateTestData();
        }

        @Test
        public void test() {
            new NewMetricsUpdateTask().inform(new MetricsUpdateEvent(MetricsUpdateEvent.Type.PORTFOLIO));

            try (final var qm = new QueryManager()) {
                final PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
                assertThat(metrics.getProjects()).isEqualTo(1);
                assertThat(metrics.getComponents()).isZero();
            }
        }

        @After
        public void tearDown() {
            PersistenceManagerFactory.tearDown();
        }

    }

    public static class PostgresTest {

        @Rule
        @SuppressWarnings("rawtypes")
        public final GenericContainer<?> container = new GenericContainer(DockerImageName.parse("postgres:14-alpine"))
                .withEnv("POSTGRES_DB", "dtrack")
                .withEnv("POSTGRES_USER", "dtrack")
                .withEnv("POSTGRES_PASSWORD", "dtrack")
                .withExposedPorts(5432)
                .waitingFor(new HostPortWaitStrategy());

        @Before
        public void setUp() {
            final Properties jdoProps = JdoProperties.get();
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_URL, "jdbc:postgresql://localhost:" + container.getFirstMappedPort() + "/dtrack");
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_DRIVER_NAME, org.postgresql.Driver.class.getName());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_USER_NAME, "dtrack");
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_PASSWORD, "dtrack");

            final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(jdoProps, "Alpine");
            PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);

            populateTestData();
        }

        @Test
        public void test() {
            new NewMetricsUpdateTask().inform(new MetricsUpdateEvent(MetricsUpdateEvent.Type.PORTFOLIO));

            try (final var qm = new QueryManager()) {
                final PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
                assertThat(metrics.getProjects()).isEqualTo(1);
                assertThat(metrics.getComponents()).isZero();
            }
        }

        @After
        public void tearDown() {
            PersistenceManagerFactory.tearDown();
        }

    }

    protected static void populateTestData() {
        try (final var qm = new QueryManager()) {
            // TODO: Add enough data to cover all queries in the update task

            var project = new Project();
            project.setName("acme-app");
            qm.createProject(project, List.of(), false);
        }
    }

}