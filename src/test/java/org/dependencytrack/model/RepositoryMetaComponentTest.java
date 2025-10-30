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

import java.util.Date;

class RepositoryMetaComponentTest {

    @Test
    void testId() {
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setId(111L);
        Assertions.assertEquals(111L, rmc.getId());
    }

    @Test
    void testRepositoryType() {
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setRepositoryType(RepositoryType.MAVEN);
        Assertions.assertEquals(RepositoryType.MAVEN, rmc.getRepositoryType());
    }

    @Test
    void testNamespace() {
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setNamespace("My Namespace");
        Assertions.assertEquals("My Namespace", rmc.getNamespace());
    } 

    @Test
    void testName() {
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setName("My Name");
        Assertions.assertEquals("My Name", rmc.getName());
    } 
    
    @Test
    void testLatestVersion() {
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setLatestVersion("2.0.0");
        Assertions.assertEquals("2.0.0", rmc.getLatestVersion());
    } 

    @Test
    void testPublished() {
        Date date = new Date();
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setPublished(date);
        Assertions.assertEquals(date, rmc.getPublished());
    }

    @Test
    void testLastCheck() {
        Date date = new Date();
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setLastCheck(date);
        Assertions.assertEquals(date, rmc.getLastCheck());
    }
} 
