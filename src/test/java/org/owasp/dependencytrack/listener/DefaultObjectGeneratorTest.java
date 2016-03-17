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
package org.owasp.dependencytrack.listener;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.dependencytrack.config.JunitDatabaseConfiguration;
import org.owasp.dependencytrack.dao.AllDaos;
import org.owasp.dependencytrack.model.AllEntities;
import org.owasp.dependencytrack.model.Roles;
import org.owasp.dependencytrack.model.User;
import org.owasp.dependencytrack.repository.AllRepositories;
import org.owasp.dependencytrack.service.AllServices;
import org.owasp.dependencytrack.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

/**
 * Created by Jason Wraxall on 7/12/15.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {JunitDatabaseConfiguration.class,AllEntities.class,AllServices.class,AllListeners.class, HibernateJpaAutoConfiguration.class, AllRepositories.class,AllDaos.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class DefaultObjectGeneratorTest {

    @Autowired
    UserService userService;

    @Autowired
    DefaultObjectGenerator defaultObjectGenerator;

    @Before
    public void waitForInit(){
        try {
            DefaultObjectGenerator.initialised.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        assertThat("Default object has run", DefaultObjectGenerator.initialised.getCount(), is(0L));
    }

    @Test
    public void configOK() {
        assertThat(defaultObjectGenerator, is(notNullValue()));
    }

    @Test
    public void testLoadDefaultRoles() throws Exception {
        List<Roles> roleList = userService.getRoleList();
        assertThat(roleList, not(Collections.<Roles>emptyList()));
    }

    @Test
    public void testLoadDefaultUsers() throws Exception {
        assertThat(userService, not(nullValue()));
        List<User> users = userService.accountManagement();
        assertThat(users, not(Collections.<User>emptyList()));
    }
}