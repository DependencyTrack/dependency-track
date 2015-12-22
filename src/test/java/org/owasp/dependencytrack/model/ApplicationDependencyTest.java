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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * JUnit test for the {@link ApplicationDependency} class.
 */
public class ApplicationDependencyTest {

    @Test
    @Transactional
    public void testObject() {
        Application application = new Application();
        application.setId(1);
        application.setName("Sample Application");

        ApplicationVersion appVer = new ApplicationVersion();
        appVer.setId(100);
        appVer.setVersion("1.0");
        appVer.setApplication(application);

        Library library = new Library();
        library.setId(1000);
        library.setLibraryname("Sample Library");

        LibraryVersion libVer = new LibraryVersion();
        libVer.setId(10000);
        libVer.setLibraryversion("4.0");
        libVer.setLibrary(library);

        ApplicationDependency dependency = new ApplicationDependency();
        dependency.setId(100000);
        dependency.setLibraryVersion(libVer);
        dependency.setApplicationVersion(appVer);

        assertEquals(new Integer(100000), dependency.getId());
        assertNotNull(dependency.getLibraryVersion());
        assertNotNull(dependency.getApplicationVersion());

        assertEquals(new Integer(100), dependency.getApplicationVersion().getId());
        assertEquals("1.0", dependency.getApplicationVersion().getVersion());

        assertEquals(new Integer(10000), dependency.getLibraryVersion().getId());
        assertEquals("4.0", dependency.getLibraryVersion().getLibraryversion());



        ApplicationDependency cloned = (ApplicationDependency)dependency.clone();

        assertEquals(null, cloned.getId());
        assertNotNull(cloned.getLibraryVersion());
        assertNotNull(cloned.getApplicationVersion());

        assertEquals(new Integer(100), cloned.getApplicationVersion().getId());
        assertEquals("1.0", cloned.getApplicationVersion().getVersion());

        assertEquals(new Integer(10000), cloned.getLibraryVersion().getId());
        assertEquals("4.0", cloned.getLibraryVersion().getLibraryversion());

    }
}
