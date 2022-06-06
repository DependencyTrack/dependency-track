package org.dependencytrack.tasks;

import alpine.persistence.JdoProperties;
import alpine.server.persistence.PersistenceManagerFactory;
import org.apache.commons.lang3.SystemUtils;
import org.datanucleus.PropertyNames;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.MSSQLServerContainer;
import org.testcontainers.utility.DockerImageName;

import javax.jdo.JDOHelper;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assume.assumeFalse;

public class MetricsUpdateTaskMsSqlServerIT extends AbstractMetricsUpdateTaskIT {

    private static final DockerImageName IMAGE_NAME = DockerImageName.parse("mcr.microsoft.com/mssql/server:2019-latest");

    @Rule
    @SuppressWarnings("rawtypes")
    public final MSSQLServerContainer container = new MSSQLServerContainer(IMAGE_NAME).acceptLicense();

    @BeforeClass
    public static void setUpClass() {
        assumeFalse("The SQL Server image is not compatible with ARM", "aarch64".equals(SystemUtils.OS_ARCH));
    }

    @Override
    void setUpDatabase() throws Exception {
        // We need to create the database manually because the container won't do it automatically.
        final Container.ExecResult execResult = container.execInContainer("/opt/mssql-tools/bin/sqlcmd",
                "-S", "localhost",
                "-U", container.getUsername(),
                "-P", container.getPassword(),
                "-Q", "CREATE DATABASE dtrack");
        assertThat(execResult.getExitCode()).isZero();

        final Properties jdoProps = JdoProperties.get();
        jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_URL, container.getJdbcUrl() +
                ";databaseName=dtrack;sendStringParametersAsUnicode=false;trustServerCertificate=true");
        jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_DRIVER_NAME, com.microsoft.sqlserver.jdbc.SQLServerDriver.class.getName());
        jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_USER_NAME, container.getUsername());
        jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_PASSWORD, container.getPassword());

        final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(jdoProps, "Alpine");
        PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);
    }

}
