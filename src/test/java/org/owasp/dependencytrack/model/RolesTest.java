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

import org.junit.Test;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashSet;
import java.util.Set;

import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.junit.Assert.*;

/**
 * JUnit test for the {@link Permissions} class.
 */
public class RolesTest {

    @Test
    public void testStaticRoles() {
        assertEquals(Roles.ROLE.ADMIN, Roles.ROLE.getRole("admin"));
        assertEquals(Roles.ROLE.MODERATOR, Roles.ROLE.getRole("moderator"));
        assertEquals(Roles.ROLE.USER, Roles.ROLE.getRole("user"));

        assertEquals(Roles.ROLE.ADMIN, Roles.ROLE.getRole("Admin"));
        assertEquals(Roles.ROLE.MODERATOR, Roles.ROLE.getRole("ModeRator"));
        assertEquals(Roles.ROLE.USER, Roles.ROLE.getRole("USEr"));

        assertNull(null, Roles.ROLE.getRole("none"));
    }

    @Test
    @Transactional
    public void testObject() throws Exception {
        LinkedHashSet<Permissions> perms = new LinkedHashSet<>();
        Permissions p1 = new Permissions("dosomething");
        Permissions p2 = new Permissions("dosomethingelse");
        perms.add(p1);
        perms.add(p2);

        LinkedHashSet<User> users = new LinkedHashSet<>();
        User u1 = new User();
        u1.setUsername("Fred");
        User u2 = new User();
        u2.setUsername("Barney");
        users.add(u1);
        users.add(u2);

        Roles r1 = new Roles("Role 1");
        r1.setId(1);
        r1.addPermissions(perms);
        r1.addUsers(users);

        Roles r2 = new Roles();
        r2.setRole("Role 2");
        r2.setId(1);
        r2.addPermissions(perms);
        r2.addUsers(users);

        assertEquals(new Integer(1), r1.getId());
        assertEquals("Role 1", r1.getRole());
        assertEquals("Role 2", r2.getRole());
        Set<Permissions> r1permissions = r1.getPermissions();
        assertEquals(2, r1permissions.size());
        assertEquals(2, r1.getUsers().size());
        assertThat(r1permissions,hasItems(p1,p2));
        assertThat(r1.getUsers(),hasItems(u1,u2));
    }

}
