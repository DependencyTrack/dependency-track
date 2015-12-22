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

import static org.junit.Assert.assertEquals;

/**
 * JUnit test for the {@link Permissions} class.
 */
public class PermissionsTest {

    @Test
    @Transactional
    public void testObject() throws Exception {
        Set<Roles> roles = new LinkedHashSet<>();
        roles.add(new Roles("admin"));
        roles.add(new Roles("moderator"));
        roles.add(new Roles("user"));

        Permissions p1 = new Permissions("dosomething");
        p1.setId(1);
        p1.setMaprole(roles);

        Permissions p2 = new Permissions();
        p2.setPermissionname("dosomethingelse");
        p2.setId(2);
        p2.setMaprole(roles);


        assertEquals(new Integer(1), p1.getId());
        assertEquals("dosomething", p1.getPermissionname());
        assertEquals(3, p1.getMaprole().size());
        assertEquals("admin", p1.getMaprole().iterator().next().getRole());
        assertEquals("dosomethingelse", p2.getPermissionname());
    }

}
