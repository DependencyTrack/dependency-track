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
        v1.setMd5("1234");
        v1.setSha1("5678");
        v1.setUuid("82d679e9-f876-4879-9784-0c9864098b4a");
        v1.setVulnCount(100);

        LibraryVersion v2 = new LibraryVersion();
        v2.setId(100);
        v2.setLibraryversion("2.0");
        v2.setLibrary(library);
        v2.setMd5("4321");
        v2.setSha1("8765");
        v2.setUuid("a2759a18-ca45-4220-9355-a2c3db2fcd95");
        v2.setVulnCount(101);

        HashSet<LibraryVersion> versions = new HashSet<LibraryVersion>(Arrays.asList(v1, v2));
        library.setVersions(versions);

        assertEquals(new Integer(100), v1.getId());
        assertEquals("1.0", v1.getLibraryversion());
        assertEquals("1234", v1.getMd5());
        assertEquals("5678", v1.getSha1());
        assertEquals("82d679e9-f876-4879-9784-0c9864098b4a", v1.getUuid());
        assertEquals(new Integer(100), v1.getVulnCount());
        assertNotNull(v1.getLibrary());
        assertEquals(new Integer(1), v1.getLibrary().getId());
        assertEquals("Sample Library", v1.getLibrary().getLibraryname());
        assertNotNull(library.getVersions());
        assertTrue(library.getVersions().size() == 2);

        LibraryVersion cloned = (LibraryVersion)v1.clone();
        assertEquals(null, cloned.getId());
        assertEquals("1.0", cloned.getLibraryversion());
        assertEquals("1234", cloned.getMd5());
        assertEquals("5678", cloned.getSha1());
        assertNotNull(cloned.getUuid());
        assertFalse("82d679e9-f876-4879-9784-0c9864098b4a".equals(cloned.getUuid()));
        assertEquals(new Integer(0), cloned.getVulnCount());
        assertNotNull(v1.getLibrary());
        assertEquals(new Integer(1), cloned.getLibrary().getId());
        assertEquals("Sample Library", cloned.getLibrary().getLibraryname());
        assertNotNull(library.getVersions());
        assertTrue(library.getVersions().size() == 2);
    }
}
