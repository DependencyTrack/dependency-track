/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
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

        Project p1 = qm.createProject("Example Project 1", "Description 1", "1.0", null, null, null, false);
        Project p2 = qm.createProject("Example Project 2", "Description 2", "1.1", null, null, null, false);
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
