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
import org.dependencytrack.model.Component;
import org.junit.Assert;
import org.junit.Test;
import java.util.UUID;

public class ComponentIndexerTest extends PersistenceCapableTest {

    @Test
    public void getSearchFieldsTest() {
        String[] fields = ComponentIndexer.getInstance().getSearchFields();
        Assert.assertEquals(6, fields.length);
        Assert.assertEquals("uuid", fields[0]);
        Assert.assertEquals("name", fields[1]);
        Assert.assertEquals("group", fields[2]);
        Assert.assertEquals("version", fields[3]);
        Assert.assertEquals("sha1", fields[4]);
        Assert.assertEquals("description", fields[5]);
    }

    @Test
    public void getIndexTypeTest() {
        Assert.assertEquals(IndexManager.IndexType.COMPONENT, ComponentIndexer.getInstance().getIndexType());
    }

    @Test
    public void addTest() {
        Component c = new Component();
        c.setUuid(UUID.randomUUID());
        c.setGroup("acme");
        c.setName("crypto-library");
        c.setVersion("1.0.0");
        ComponentIndexer.getInstance().add(c);
        ComponentIndexer.getInstance().commit();
        SearchManager searchManager = new SearchManager();
        SearchResult result = searchManager.searchIndex(ComponentIndexer.getInstance(), c.getUuid().toString(), 10);
        Assert.assertEquals(1, result.getResults().size());
        Assert.assertEquals(1, result.getResults().get("component").size());
    }

    @Test
    public void removeTest() {
        Component c = new Component();
        c.setUuid(UUID.randomUUID());
        c.setGroup("acme");
        c.setName("crypto-library");
        c.setVersion("1.0.0");
        ComponentIndexer.getInstance().add(c);
        ComponentIndexer.getInstance().commit();
        SearchManager searchManager = new SearchManager();
        ComponentIndexer.getInstance().remove(c);
        ComponentIndexer.getInstance().commit();
        SearchResult result = searchManager.searchIndex(ComponentIndexer.getInstance(), c.getUuid().toString(), 10);
        Assert.assertEquals(1, result.getResults().size());
        Assert.assertEquals(0, result.getResults().get("component").size());
    }

    @Test
    public void reindexTest() {
        ComponentIndexer.getInstance().reindex();
    }
}
