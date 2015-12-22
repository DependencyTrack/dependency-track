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

import org.hibernate.engine.jdbc.BlobProxy;
import org.hibernate.engine.jdbc.ClobProxy;
import org.junit.Test;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * JUnit test for the {@link License} class.
 */
public class LicenseTest {

    @Test
    @Transactional
    public void testObject() throws Exception {
        License license = new License();
        license.setId(1);
        license.setLicensename("GPLv3");
        license.setFilename("license.txt");
        license.setContenttype("text/plain");

        license.setText(BlobProxy.generateProxy("License Test".getBytes("UTF-8")));
        license.setUrl(ClobProxy.generateProxy("http://localhost/license.txt") );

        assertEquals(new Integer(1), license.getId());
        assertEquals("GPLv3", license.getLicensename());
        assertEquals("license.txt", license.getFilename());
        assertEquals("text/plain", license.getContenttype());
        assertTrue(license.getText().length() == 12);
        assertTrue(license.getUrl().length() == 28);

        License cloned = (License)license.clone();
        assertEquals(null, cloned.getId());
        assertEquals("GPLv3", cloned.getLicensename());
        assertEquals("license.txt", cloned.getFilename());
        assertEquals("text/plain", cloned.getContenttype());
        assertTrue(cloned.getText().length() == 12);
        assertTrue(cloned.getUrl().length() == 28);
    }
}
