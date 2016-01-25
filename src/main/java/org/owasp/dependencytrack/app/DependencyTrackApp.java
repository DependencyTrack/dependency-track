/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.app;

import org.owasp.dependencytrack.config.DatabaseConfiguration;
import org.owasp.dependencytrack.config.EventConfiguration;
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
        AllControllers.class,
        EventConfiguration.class})
@EntityScan(basePackageClasses = Application.class)
public class DependencyTrackApp {

    private static final Logger logger = LoggerFactory.getLogger(DependencyTrackApp.class);

    public static void main(final String[] args) {

        SpringApplication.run(DependencyTrackApp.class, args);
    }


}