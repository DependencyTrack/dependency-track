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
package org.owasp.dependencytrack.dao;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.dependencytrack.config.JunitDatabaseConfiguration;
import org.owasp.dependencytrack.model.AllEntities;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.owasp.dependencytrack.repository.AllRepositories;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {JunitDatabaseConfiguration.class,AllEntities.class,HibernateJpaAutoConfiguration.class, AllRepositories.class,AllDaos.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class ApplicationVersionDaoTest {

    @Autowired
    ApplicationDao applicationDao;

    @Autowired
    ApplicationVersionDao applicationVersionDao;

    private Application application;

    @Before
    public void before() {
        application = new Application();
        application.setName("Application A");
        applicationDao.addApplication(application, "1.0.0");
    }

    @Test
    public void getApplicationVersionTest() {
        Application application = applicationDao.listApplications().get(0);
        ApplicationVersion version = application.getVersions().iterator().next();
        assertEquals("1.0.0", version.getVersion());
        assertEquals("Application A", version.getApplication().getName());
    }

    @Test
    public void addApplicationVersionTest() {
        // add a new version to the application
        applicationVersionDao.addApplicationVersion(application.getId(), "1.1.0");

        Application application = applicationDao.listApplications().get(0);
        assertEquals(2, application.getVersions().size());

        for (ApplicationVersion version : application.getVersions()) {
            assertTrue(version.getVersion().equals("1.0.0") || version.getVersion().equals("1.1.0"));
        }
    }

    @Test
    public void deleteApplicationVersionTest() {
        Application application = applicationDao.listApplications().get(0);
        Set<ApplicationVersion> versions = application.getVersions();

        assertEquals(1, versions.size());

        for (ApplicationVersion version: versions) {
            applicationVersionDao.deleteApplicationVersion(version.getId());
        }

        ApplicationVersion version = applicationVersionDao.getApplicationVersion(3);
        assertTrue(version.getVersion() == null);

        application = applicationDao.listApplications().get(0);
        assertEquals(0, application.getVersions().size());
    }

}