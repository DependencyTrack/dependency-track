package org.dependencytrack.tasks;

import alpine.persistence.JdoProperties;
import alpine.server.persistence.PersistenceManagerFactory;
import org.datanucleus.PropertyNames;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.junit.Rule;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.jdo.JDOHelper;
import java.util.Properties;

public class MetricsUpdateTaskMySqlIT extends AbstractMetricsUpdateTaskIT {

    private static final DockerImageName IMAGE_NAME = DockerImageName.parse("mysql:5.7");

    @Rule
    @SuppressWarnings("rawtypes")
    public final MySQLContainer container = new MySQLContainer(IMAGE_NAME)
            .withConfigurationOverride("testcontainers/mysql");

    @Override
    void setUpDatabase() {
        final Properties jdoProps = JdoProperties.get();
        jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_URL, container.getJdbcUrl());
        jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_DRIVER_NAME, com.mysql.cj.jdbc.Driver.class.getName());
        jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_USER_NAME, container.getUsername());
        jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_PASSWORD, container.getPassword());

        final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(jdoProps, "Alpine");
        PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);
    }

}
