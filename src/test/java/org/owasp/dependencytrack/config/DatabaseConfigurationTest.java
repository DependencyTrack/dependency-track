package org.owasp.dependencytrack.config;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.dependencytrack.repository.AllRepositories;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.sql.DataSource;

import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

/**
 * Created by Jason Wraxall on 7/12/15.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {DatabaseConfiguration.class, AllRepositories.class, HibernateJpaAutoConfiguration.class})
public class DatabaseConfigurationTest {

    @Autowired
    DataSource dataSource;


    @Test
    public void testDataSource() throws Exception {
        assertThat(dataSource,not(nullValue()));
    }
}