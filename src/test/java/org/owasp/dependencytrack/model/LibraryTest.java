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

import java.util.Arrays;
import java.util.HashSet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * JUnit test for the {@link Library} class.
 */
public class LibraryTest {

    @Test
    @Transactional
    public void testObject() {
        LibraryVendor vendor = new LibraryVendor();
        vendor.setId(1);
        vendor.setVendor("OWASP");

        License license = new License();
        license.setId(10);
        license.setLicensename("GPLv3");

        Application application = new Application();
        application.setId(100);
        application.setName("Sample Application");

        LibraryVersion v1 = new LibraryVersion();
        v1.setId(1000);
        v1.setLibraryversion("1.0");

        LibraryVersion v2 = new LibraryVersion();
        v2.setId(10000);
        v2.setLibraryversion("2.0");

        HashSet<LibraryVersion> versions = new HashSet<LibraryVersion>(Arrays.asList(v1, v2));

        Library library = new Library();
        library.setId(99999);
        library.setLanguage("Java");
        library.setLibraryname("Sample Library");
        library.setLibraryVendor(vendor);
        library.setLicense(license);
        library.setVersions(versions);

        assertEquals(new Integer(99999), library.getId());
        assertEquals("Java", library.getLanguage());
        assertEquals("Sample Library", library.getLibraryname());
        assertNotNull(library.getLibraryVendor());
        assertEquals(new Integer(1), library.getLibraryVendor().getId());
        assertEquals("OWASP", library.getLibraryVendor().getVendor());
        assertNotNull(library.getLicense());
        assertEquals(new Integer(10), library.getLicense().getId());
        assertEquals("GPLv3", library.getLicense().getLicensename());
        assertNotNull(library.getVersions());
        assertTrue(library.getVersions().size() == 2);

        Library cloned = (Library)library.clone();
        assertEquals(null, cloned.getId());
        assertEquals("Java", cloned.getLanguage());
        assertEquals("Sample Library", cloned.getLibraryname());
        assertNotNull(cloned.getLibraryVendor());
        assertEquals(new Integer(1), cloned.getLibraryVendor().getId());
        assertEquals("OWASP", cloned.getLibraryVendor().getVendor());
        assertNotNull(cloned.getLicense());
        assertEquals(new Integer(10), cloned.getLicense().getId());
        assertEquals("GPLv3", cloned.getLicense().getLicensename());
        //todo: investigate this
        //assertNotNull(cloned.getVersions());
        //assertTrue(cloned.getVersions().size() == 2);
    }
}
