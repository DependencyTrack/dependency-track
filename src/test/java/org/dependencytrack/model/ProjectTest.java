/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.model;

import org.dependencytrack.PersistenceCapableTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.UUID;

class ProjectTest extends PersistenceCapableTest {

    @Test
    void testProjectPersistence() {
        Project p1 = qm.createProject("Example Project 1", "Description 1", "1.0", null, null, null, true, false);
        Project p2 = qm.createProject("Example Project 2", "Description 2", "1.1", null, null, null, true, false);
        Bom bom = qm.createBom(p1, new Date(), Bom.Format.CYCLONEDX, "1.1", 1, UUID.randomUUID().toString());

        Assertions.assertEquals("Example Project 1", p1.getName());
        Assertions.assertEquals("Example Project 2", p2.getName());

        Assertions.assertNotNull(p1.getUuid());
        Assertions.assertNotNull(p2.getUuid());

        Assertions.assertNotNull(bom.getProject());
        Assertions.assertEquals("Example Project 1", bom.getProject().getName());
        Assertions.assertEquals("Description 1", bom.getProject().getDescription());
        Assertions.assertEquals("1.0", bom.getProject().getVersion());

        Assertions.assertNotNull(bom.getUuid());
        Assertions.assertNotNull(bom.getImported());
    }

    @Test
    void testProjectPersistActiveFieldDefaultsToTrue() {

        Project project = new Project();
        project.setName("Example Project 1");
        project.setDescription("Description 1");
        project.setVersion("1.0");

        Project persistedProject = qm.createProject(project, null, false);

        Assertions.assertTrue(persistedProject.isActive());
    }
}
