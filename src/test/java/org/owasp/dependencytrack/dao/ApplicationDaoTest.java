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