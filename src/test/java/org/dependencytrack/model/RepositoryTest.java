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

class RepositoryTest {

    @Test
    void testId() {
        Repository repo = new Repository();
        repo.setId(111L);
        Assertions.assertEquals(111L, repo.getId());
    }

    @Test
    void testType() {
        Repository repo = new Repository();
        repo.setType(RepositoryType.MAVEN);
        Assertions.assertEquals(RepositoryType.MAVEN, repo.getType());
    }

    @Test
    void testIdentifier() {
        Repository repo = new Repository();
        repo.setIdentifier("maven-central");
        Assertions.assertEquals("maven-central", repo.getIdentifier());
    }

    @Test
    void testUrl() {
        Repository repo = new Repository();
        repo.setUrl("https://repo.maven.apache.org/maven2");
        Assertions.assertEquals("https://repo.maven.apache.org/maven2", repo.getUrl());
    }

    @Test
    void testResolutionOrder() {
        Repository repo = new Repository();
        repo.setResolutionOrder(5);
        Assertions.assertEquals(5, repo.getResolutionOrder());
    }

    @Test
    void testEnabled() {
        Repository repo = new Repository();
        repo.setEnabled(true);
        Assertions.assertTrue(repo.isEnabled());
    }

    @Test
    void testAuthenticationRequiredTrue() {
        Repository repo = new Repository();
        repo.setAuthenticationRequired(true);
        Assertions.assertTrue(repo.isAuthenticationRequired());
    }

    @Test
    void testAuthenticationRequiredFalse() {
        Repository repo = new Repository();
        repo.setAuthenticationRequired(false);
        Assertions.assertFalse(repo.isAuthenticationRequired());
    }
} 
