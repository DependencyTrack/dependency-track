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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

class TagTest {

    @Test
    void testId() {
        Tag tag = new Tag();
        tag.setId(111L);
        Assertions.assertEquals(111L, tag.getId());
    } 

    @Test
    void testName() {
        Tag tag = new Tag();
        tag.setName("java");
        Assertions.assertEquals("java", tag.getName());
    } 

    @Test
    void testProjects() {
        Set<Project> projects = new HashSet<>();
        Project project = new Project();
        projects.add(project);
        Tag tag = new Tag();
        tag.setProjects(projects);
        Assertions.assertEquals(1, tag.getProjects().size());
        Assertions.assertEquals(project, tag.getProjects().iterator().next());
    } 

    @Test
    void testEquals() {
        Tag t1 = new Tag();
        t1.setName("foo");
        Tag t2 = new Tag();
        t2.setName("bar");
        Tag t3 = new Tag();
        t3.setName("foo");
        Assertions.assertFalse(t1.equals(t2));
        Assertions.assertTrue(t1.equals(t3));
    }
} 
