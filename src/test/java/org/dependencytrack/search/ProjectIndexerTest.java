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
package org.dependencytrack.search;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.search.document.ProjectDocument;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.awaitility.Awaitility.await;

class ProjectIndexerTest extends PersistenceCapableTest {

    @Test
    void getSearchFieldsTest() {
        String[] fields = ProjectIndexer.getInstance().getSearchFields();
        Assertions.assertEquals(5, fields.length);
        Assertions.assertEquals("uuid", fields[0]);
        Assertions.assertEquals("name", fields[1]);
        Assertions.assertEquals("version", fields[2]);
        Assertions.assertEquals("properties", fields[3]);
        Assertions.assertEquals("description", fields[4]);
    }

    @Test
    void getIndexTypeTest() {
        Assertions.assertEquals(IndexManager.IndexType.PROJECT, ProjectIndexer.getInstance().getIndexType());
    }

    @Test
    void addTest() {
        Project p = new Project();
        p.setUuid(UUID.randomUUID());
        p.setName("Acme Application");
        p.setVersion("1.0.0");
        ProjectIndexer.getInstance().add(new ProjectDocument(p));
        commitIndex();

        await().untilAsserted(() -> {
            SearchResult result = SearchManager.searchIndex(ProjectIndexer.getInstance(), p.getUuid().toString(), 10);
            Assertions.assertEquals(1, result.getResults().size());
            Assertions.assertEquals(1, result.getResults().get("project").size());
        });
    }

    @Test
    void removeTest() {
        Project p = new Project();
        p.setUuid(UUID.randomUUID());
        p.setName("Acme Application");
        p.setVersion("1.0.0");
        ProjectIndexer.getInstance().add(new ProjectDocument(p));
        commitIndex();
        ProjectIndexer.getInstance().remove(new ProjectDocument(p));
        commitIndex();

        await().untilAsserted(() -> {
            SearchResult result = SearchManager.searchIndex(ProjectIndexer.getInstance(), p.getUuid().toString(), 10);
            Assertions.assertEquals(1, result.getResults().size());
            Assertions.assertEquals(0, result.getResults().get("project").size());
        });
    }

    @Test
    void reindexTest() {
        ProjectIndexer.getInstance().reindex();
    }

    private static void commitIndex() {
        IndexManagerTestUtil.commitIndex(ProjectIndexer.getInstance());
    }
}
