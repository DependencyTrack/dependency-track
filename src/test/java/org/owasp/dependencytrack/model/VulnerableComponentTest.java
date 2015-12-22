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

import org.junit.Test;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * JUnit test for the {@link VulnerableComponent} class.
 */
public class VulnerableComponentTest {

    @Test
    @Transactional
    public void testObject() throws Exception {
        Library library = new Library();
        library.setLibraryname("Library Name");

        LibraryVersion version = new LibraryVersion();
        version.setLibrary(library);
        version.setLibraryversion("1.0");

        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setName("CVE-2015-1000");
        List<Vulnerability> vulnList = new ArrayList<>();
        vulnList.add(vulnerability);

        Date scanDate = new Date();

        ScanResult result = new ScanResult();
        result.setId(1);
        result.setLibraryVersion(version);
        result.setVulnerability(vulnerability);
        result.setScanDate(scanDate);

        VulnerableComponent vc = new VulnerableComponent();
        vc.setLibraryVersion(version);
        vc.setScanResult(result);
        vc.setVulnerabilities(vulnList);

        assertEquals("1.0", vc.getLibraryVersion().getLibraryversion());
        assertEquals(1, vc.getVulnerabilities().size());
        assertEquals("CVE-2015-1000", vc.getVulnerabilities().get(0).getName());
        assertEquals(scanDate, vc.getScanResult().getScanDate());

        Vulnerability vulnerability2 = new Vulnerability();
        vulnerability2.setName("CVE-2015-1001");
        vc.addVulnerability(vulnerability2);

        assertEquals(2, vc.getVulnerabilities().size());
        assertEquals("CVE-2015-1001", vc.getVulnerabilities().get(1).getName());
    }
}
