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

public class ComponentOccurrenceTest extends PersistenceCapableTest {

    @Test
    public void testLocationMoreThan255Length() {
        final var project = new Project();
        project.setName("project");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("component");
        qm.persist(component);

        ComponentOccurrence occ = new ComponentOccurrence();
        occ.setComponent(component);
        occ.setLocation("a".repeat(300));
        qm.persist(occ);
        qm.getPersistenceManager().evictAll();

        final var persistedOccurrence = qm.getObjectById(ComponentOccurrence.class, occ.getId());
        Assertions.assertEquals(300, persistedOccurrence.getLocation().length());
    }
} 
