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
package org.owasp.dependencytrack.model;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.transaction.annotation.Transactional;

/**
 * JUnit test for the {@link User} class.
 */
public class UserTest {

    @Test
    @Transactional
    public void testObject() {
        Roles role = new Roles("admin");

        User user = new User();
        user.setId(1);
        user.setUsername("testuser");
        user.setPassword("password");
        user.setIsLdap(true);
        user.setRoles(role);

        assertEquals(new Integer(1), user.getId());
        assertEquals("testuser", user.getUsername());
        assertEquals("password", user.getPassword());
        assertEquals(true, user.isLdap());
        assertEquals("admin", role.getRole());
    }
}
