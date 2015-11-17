package org.owasp.dependencytrack.dao;

import org.hamcrest.CoreMatchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.dependencytrack.config.ApplicationConfiguration;
import org.owasp.dependencytrack.config.DatabaseConfguration;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.service.AllServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

/**
 * Created by jason on 15/11/15.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {ApplicationConfiguration.class,
        AllDaos.class, AllServices.class, DatabaseConfguration.class
})
public class ApplicationDaoTest {

    @Autowired
    ApplicationDao applicationDao;

    @Test
    @Transactional
    public void testListApplications() throws Exception {
        assertThat(applicationDao, not(nullValue()));
        List<Application> applications = applicationDao.listApplications();
        assertThat(applications, not(CoreMatchers.<List<Application>>nullValue()));
    }

//    @Test
//    public void testAddApplication() throws Exception {
//
//    }
//
//    @Test
//    public void testUpdateApplication() throws Exception {
//
//    }
//
//    @Test
//    public void testDeleteApplication() throws Exception {
//
//    }
//
//    @Test
//    public void testSearchApplications() throws Exception {
//
//    }
//
//    @Test
//    public void testSearchApplicationsVersion() throws Exception {
//
//    }
//
//    @Test
//    public void testSearchAllApplications() throws Exception {
//
//    }
//
//    @Test
//    public void testSearchAllApplicationsVersions() throws Exception {
//
//    }
//
//    @Test
//    public void testCoarseSearchApplications() throws Exception {
//
//    }
//
//    @Test
//    public void testCoarseSearchApplicationVersions() throws Exception {
//
//    }
}