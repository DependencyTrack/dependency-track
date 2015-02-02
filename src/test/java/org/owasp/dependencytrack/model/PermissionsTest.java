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
