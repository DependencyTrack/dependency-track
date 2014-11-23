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
 *
 * Copyright (c) Axway. All Rights Reserved.
 */

package org.owasp.dependencytrack.model;

import org.junit.Test;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.HashSet;

import static org.junit.Assert.*;

/**
 * JUnit test for the {@link LibraryVersion} class.
 */
public class LibraryVersionTest {

    @Test
    @Transactional
    public void testObject() {
        Library library = new Library();
        library.setId(1);
        library.setLibraryname("Sample Library");

        LibraryVersion v1 = new LibraryVersion();
        v1.setId(100);
        v1.setLibraryversion("1.0");
        v1.setLibrary(library);

        LibraryVersion v2 = new LibraryVersion();
        v2.setId(100);
        v2.setLibraryversion("2.0");
        v2.setLibrary(library);

        HashSet<LibraryVersion> versions = new HashSet<LibraryVersion>(Arrays.asList(v1, v2));
        library.setVersions(versions);

        assertEquals(new Integer(100), v1.getId());
        assertEquals("1.0", v1.getLibraryversion());
        assertNotNull(v1.getLibrary());
        assertEquals(new Integer(1), v1.getLibrary().getId());
        assertEquals("Sample Library", v1.getLibrary().getLibraryname());

        assertNotNull(library.getVersions());
        assertTrue(library.getVersions().size() == 2);
    }
}
