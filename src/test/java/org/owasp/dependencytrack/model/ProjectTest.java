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

import org.junit.Assert;
import org.junit.Test;
import org.owasp.dependencytrack.BaseTest;
import org.owasp.dependencytrack.persistence.QueryManager;
import java.util.Date;

public class ProjectTest extends BaseTest {

    @Test
    public void testProjectPersistence() throws Exception {
        QueryManager qm = new QueryManager();

        Project p1 = qm.createProject("Example Project 1", "Description 1", "1.0", null, null, false);
        Project p2 = qm.createProject("Example Project 2", "Description 2", "1.1", null, null, false);
        Scan scan = qm.createScan(p1, new Date(), new Date());

        Assert.assertEquals("Example Project 1", p1.getName());
        Assert.assertEquals("Example Project 2", p2.getName());

        Assert.assertNotNull(p1.getUuid());
        Assert.assertNotNull(p2.getUuid());

        Assert.assertNotNull(scan.getProject());
        Assert.assertEquals("Example Project 1", scan.getProject().getName());
        Assert.assertEquals("Description 1", scan.getProject().getDescription());
        Assert.assertEquals("1.0", scan.getProject().getVersion());

        Assert.assertNotNull(scan.getUuid());
        Assert.assertNotNull(scan.getExecuted());
        Assert.assertNotNull(scan.getImported());

        qm.close();
    }
}
