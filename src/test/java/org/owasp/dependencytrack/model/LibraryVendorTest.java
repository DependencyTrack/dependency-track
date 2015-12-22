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

import static org.junit.Assert.*;

/**
 * JUnit test for the {@link LibraryVendor} class.
 */
public class LibraryVendorTest {

    @Test
    @Transactional
    public void testObject() {
        Library lib1 = new Library();
        lib1.setId(1);
        lib1.setLibraryname("Sample Library #1");

        Library lib2 = new Library();
        lib2.setId(2);
        lib2.setLibraryname("Sample Library #2");

        HashSet<Library> libs = new HashSet<Library>(Arrays.asList(lib1, lib2));

        LibraryVendor vendor = new LibraryVendor();
        vendor.setId(1);
        vendor.setVendor("OWASP");
        vendor.setLibraries(libs);

        assertEquals(new Integer(1), vendor.getId());
        assertEquals("OWASP", vendor.getVendor());
        assertNotNull(vendor.getLibraries());
        assertTrue(vendor.getLibraries().size() == 2);

        LibraryVendor cloned = (LibraryVendor)vendor.clone();
        assertEquals(null, cloned.getId());
        assertEquals("OWASP", cloned.getVendor());
        //todo: investigate this
        //assertNotNull(cloned.getLibraries());
        //assertTrue(cloned.getLibraries().size() == 2);
    }
}
