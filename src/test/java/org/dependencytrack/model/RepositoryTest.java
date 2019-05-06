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

public class RepositoryTest {
    
    @Test
    public void testId() {
        Repository repo = new Repository();
        repo.setId(111L);
        Assert.assertEquals(111L, repo.getId());
    }

    @Test
    public void testType() {
        Repository repo = new Repository();
        repo.setType(RepositoryType.MAVEN);
        Assert.assertEquals(RepositoryType.MAVEN, repo.getType());
    } 

    @Test
    public void testIdentifier() {
        Repository repo = new Repository();
        repo.setIdentifier("maven-central");
        Assert.assertEquals("maven-central", repo.getIdentifier());
    }

    @Test
    public void testUrl() {
        Repository repo = new Repository();
        repo.setUrl("https://repo.maven.apache.org/maven2");
        Assert.assertEquals("https://repo.maven.apache.org/maven2", repo.getUrl());
    } 

    @Test
    public void testResolutionOrder() {
        Repository repo = new Repository();
        repo.setResolutionOrder(5);
        Assert.assertEquals(5, repo.getResolutionOrder());
    } 

    @Test
    public void testEnabled() {
        Repository repo = new Repository();
        repo.setEnabled(true);
        Assert.assertTrue(repo.isEnabled());
    }
} 
