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
package org.dependencytrack.search;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.junit.Assert;
import org.junit.Test;
import java.util.UUID;

public class ProjectIndexerTest extends PersistenceCapableTest {

    @Test
    public void getSearchFieldsTest() {
        String[] fields = ProjectIndexer.getInstance().getSearchFields();
        Assert.assertEquals(5, fields.length);
        Assert.assertEquals("uuid", fields[0]);
        Assert.assertEquals("name", fields[1]);
        Assert.assertEquals("version", fields[2]);
        Assert.assertEquals("properties", fields[3]);
        Assert.assertEquals("description", fields[4]);
    }

    @Test
    public void getIndexTypeTest() {
        Assert.assertEquals(IndexManager.IndexType.PROJECT, ProjectIndexer.getInstance().getIndexType());
    }

    @Test
    public void addTest() {
        Project p = new Project();
        p.setUuid(UUID.randomUUID());
        p.setName("Acme Application");
        p.setVersion("1.0.0");
        ProjectIndexer.getInstance().add(p);
        ProjectIndexer.getInstance().commit();
        SearchManager searchManager = new SearchManager();
        SearchResult result = searchManager.searchIndex(ProjectIndexer.getInstance(), p.getUuid().toString(), 10);
        Assert.assertEquals(1, result.getResults().size());
        Assert.assertEquals(1, result.getResults().get("project").size());
    }

    @Test
    public void removeTest() {
        Project p = new Project();
        p.setUuid(UUID.randomUUID());
        p.setName("Acme Application");
        p.setVersion("1.0.0");
        ProjectIndexer.getInstance().add(p);
        ProjectIndexer.getInstance().commit();
        SearchManager searchManager = new SearchManager();
        ProjectIndexer.getInstance().remove(p);
        ProjectIndexer.getInstance().commit();
        SearchResult result = searchManager.searchIndex(ProjectIndexer.getInstance(), p.getUuid().toString(), 10);
        Assert.assertEquals(1, result.getResults().size());
        Assert.assertEquals(0, result.getResults().get("project").size());
    }

    @Test
    public void reindexTest() {
        ProjectIndexer.getInstance().reindex();
    }
}
