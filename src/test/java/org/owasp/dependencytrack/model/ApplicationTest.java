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
import static org.junit.Assert.assertNull;

import org.junit.Test;
import org.springframework.transaction.annotation.Transactional;

/**
 * JUnit test for the {@link Application} class.
 */
public class ApplicationTest {

    @Test
    @Transactional
    public void testObject() {
        Application application = new Application();
        application.setId(1);
        application.setName("Test Application");

        assertNull(application.getVersions());
        assertEquals(new Integer(1), application.getId());
        assertEquals("Test Application", application.getName());

        Application cloned = (Application)application.clone();
        assertEquals(null, cloned.getId());
        assertEquals("Test Application", cloned.getName());
    }
}
