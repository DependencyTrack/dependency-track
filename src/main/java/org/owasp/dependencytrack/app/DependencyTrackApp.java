package org.owasp.dependencytrack.app;

import org.owasp.dependencytrack.config.DatabaseConfiguration;
import org.owasp.dependencytrack.config.PropertyConfiguration;
import org.owasp.dependencytrack.config.SecurityConfiguration;
import org.owasp.dependencytrack.controller.AllControllers;
import org.owasp.dependencytrack.dao.AllDaos;
import org.owasp.dependencytrack.listener.AllListeners;
import org.owasp.dependencytrack.model.AllEntities;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.repository.AllRepositories;
import org.owasp.dependencytrack.service.AllServices;
import org.owasp.dependencytrack.tasks.AllTasks;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.velocity.VelocityAutoConfiguration;
import org.springframework.boot.orm.jpa.EntityScan;
import org.springframework.context.annotation.Import;

/**
 * Created by Jason Wraxall on 26/11/15.
 */
@SpringBootApplication(exclude = {VelocityAutoConfiguration.class,
        JpaRepositoriesAutoConfiguration.class,
        DataSourceAutoConfiguration.class})
@Import({PropertyConfiguration.class,
        DatabaseConfiguration.class,
        AllEntities.class,
        AllDaos.class,
        AllRepositories.class,
        SecurityConfiguration.class,
        AllListeners.class,
        AllServices.class,
        AllTasks.class,
        AllControllers.class})
@EntityScan(basePackageClasses = Application.class)
public class DependencyTrackApp {

    private static final Logger logger = LoggerFactory.getLogger(DependencyTrackApp.class);

    public static void main(final String[] args) {

        SpringApplication.run(DependencyTrackApp.class, args);
    }


}