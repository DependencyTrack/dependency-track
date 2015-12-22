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
import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.springframework.transaction.annotation.Transactional;

/**
 * JUnit test for the {@link ApplicationVersion} class.
 */
public class ApplicationVersionTest {

    @Test
    @Transactional
    public void testObject() {
        Application application = new Application();
        application.setId(1);
        application.setName("Test Application");

        ApplicationVersion v1 = new ApplicationVersion();
        v1.setId(101);
        v1.setVersion("1.0");
        v1.setApplication(application);
        v1.setVulnCount(100);

        assertEquals(new Integer(101), v1.getId());
        assertEquals("1.0", v1.getVersion());
        assertNotNull(v1.getApplication());
        assertEquals(new Integer(1), v1.getApplication().getId());
        assertEquals(new Integer(100), v1.getVulnCount());

        ApplicationVersion v2 = (ApplicationVersion)v1.clone();
        assertEquals(null, v2.getId());
        assertEquals("1.0", v2.getVersion());
        assertNotNull(v2.getApplication());
        assertEquals(new Integer(1), v2.getApplication().getId());
        assertEquals(new Integer(100), v2.getVulnCount());
    }
}
