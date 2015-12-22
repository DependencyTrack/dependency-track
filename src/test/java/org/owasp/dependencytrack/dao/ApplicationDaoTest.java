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

import org.hibernate.SessionFactory;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.dependencytrack.config.DatabaseConfiguration;
import org.owasp.dependencytrack.model.AllEntities;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.repository.AllRepositories;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * Created by jason on 15/11/15.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {DatabaseConfiguration.class,AllEntities.class,HibernateJpaAutoConfiguration.class, AllRepositories.class,AllDaos.class})
@Rollback
public class ApplicationDaoTest {

    @Autowired
    ApplicationDao applicationDao;

    @Autowired
    SessionFactory sessionFactory;

    @Test
    @Transactional
    public void testApplicationDaoMethods() throws Exception {
        assertThat(sessionFactory, not(nullValue()));
        assertThat(applicationDao, not(nullValue()));
        List<Application> applications = applicationDao.listApplications();
        assertThat(applications, not(nullValue()));
        int size = applications.size();
        Application application = new Application();
        application.setName("Boris");
        applicationDao.addApplication(application,"newversion");
        applications = applicationDao.listApplications();
        assertThat(applications.size(),is(size+1));
    }


}