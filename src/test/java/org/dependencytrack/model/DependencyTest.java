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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.model;

import org.junit.Assert;
import org.junit.Test;
import java.util.Date;

public class DependencyTest {

    @Test
    public void testId() {
        Dependency dependency = new Dependency();
        dependency.setId(111L);
        Assert.assertEquals(111L, dependency.getId());
    }

    @Test
    public void testProject() {
        Project project = new Project();
        Dependency dependency = new Dependency();
        dependency.setProject(project);
        Assert.assertEquals(project, dependency.getProject());
    }

    @Test
    public void testComponent() {
        Component component = new Component();
        Dependency dependency = new Dependency();
        dependency.setComponent(component);
        Assert.assertEquals(component, dependency.getComponent());
    }

    @Test
    public void testAddedBy() {
        Dependency dependency = new Dependency();
        dependency.setAddedBy("John Doe");
        Assert.assertEquals("John Doe", dependency.getAddedBy());
    } 

    @Test
    public void testAddedOn() {
        Date date = new Date();
        Dependency dependency = new Dependency();
        dependency.setAddedOn(date);
        Assert.assertEquals(date, dependency.getAddedOn());
    }

    @Test
    public void testNotes() {
        Dependency dependency = new Dependency();
        dependency.setNotes("My notes here");
        Assert.assertEquals("My notes here", dependency.getNotes());
    }
} 
