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

public class RepositoryMetaComponentTest {

    @Test
    public void testId() {
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setId(111L);
        Assert.assertEquals(111L, rmc.getId());
    }

    @Test
    public void testRepositoryType() {
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setRepositoryType(RepositoryType.MAVEN);
        Assert.assertEquals(RepositoryType.MAVEN, rmc.getRepositoryType());
    }

    @Test
    public void testNamespace() {
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setNamespace("My Namespace");
        Assert.assertEquals("My Namespace", rmc.getNamespace());
    } 

    @Test
    public void testName() {
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setName("My Name");
        Assert.assertEquals("My Name", rmc.getName());
    } 
    
    @Test
    public void testLatestVersion() {
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setLatestVersion("2.0.0");
        Assert.assertEquals("2.0.0", rmc.getLatestVersion());
    } 

    @Test
    public void testPublished() {
        Date date = new Date();
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setPublished(date);
        Assert.assertEquals(date, rmc.getPublished());
    }

    @Test
    public void testLastCheck() {
        Date date = new Date();
        RepositoryMetaComponent rmc = new RepositoryMetaComponent();
        rmc.setLastCheck(date);
        Assert.assertEquals(date, rmc.getLastCheck());
    }
} 
