package org.owasp.dependencytrack.listener;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.dependencytrack.config.DatabaseConfiguration;
import org.owasp.dependencytrack.dao.AllDaos;
import org.owasp.dependencytrack.model.AllEntities;
import org.owasp.dependencytrack.model.Roles;
import org.owasp.dependencytrack.model.User;
import org.owasp.dependencytrack.repository.AllRepositories;
import org.owasp.dependencytrack.service.AllServices;
import org.owasp.dependencytrack.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;

import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

/**
 * Created by Jason Wraxall on 7/12/15.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {DatabaseConfiguration.class,AllEntities.class,AllServices.class,AllListeners.class, HibernateJpaAutoConfiguration.class, AllRepositories.class,AllDaos.class})
@Rollback
public class DefaultObjectGeneratorTest {

    @Autowired
    UserService userService;

    @Autowired
    DefaultObjectGenerator defaultObjectGenerator;



    @Test
    @Transactional
    public void testLoadDefaultRoles() throws Exception {
        List<Roles> roleList = userService.getRoleList();
        assertThat(roleList, not(Collections.<Roles>emptyList()));
    }

    @Test
    @Transactional
    public void testLoadDefaultUsers() throws Exception {
        assertThat(userService, not(nullValue()));
        List<User> users = userService.accountManagement();
        assertThat(users,not(Collections.<User>emptyList()));
    }
}