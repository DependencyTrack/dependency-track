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
import org.dependencytrack.model.ServiceComponent;
import org.junit.Assert;
import org.junit.Test;
import java.util.UUID;

public class ServiceComponentIndexerTest extends PersistenceCapableTest {

    @Test
    public void getSearchFieldsTest() {
        String[] fields = ServiceComponentIndexer.getInstance().getSearchFields();
        Assert.assertEquals(6, fields.length);
        Assert.assertEquals("uuid", fields[0]);
        Assert.assertEquals("name", fields[1]);
        Assert.assertEquals("group", fields[2]);
        Assert.assertEquals("version", fields[3]);
        Assert.assertEquals("url", fields[4]);
        Assert.assertEquals("description", fields[5]);
    }

    @Test
    public void getIndexTypeTest() {
        Assert.assertEquals(IndexManager.IndexType.SERVICECOMPONENT, ServiceComponentIndexer.getInstance().getIndexType());
    }

    @Test
    public void addTest() {
        ServiceComponent s = new ServiceComponent();
        s.setUuid(UUID.randomUUID());
        s.setGroup("acme");
        s.setName("stock-ticker");
        s.setVersion("1.0.0");
        ServiceComponentIndexer.getInstance().add(s);
        ServiceComponentIndexer.getInstance().commit();
        SearchManager searchManager = new SearchManager();
        SearchResult result = searchManager.searchIndex(ServiceComponentIndexer.getInstance(), s.getUuid().toString(), 10);
        Assert.assertEquals(1, result.getResults().size());
        Assert.assertEquals(1, result.getResults().get("servicecomponent").size());
    }

    @Test
    public void removeTest() {
        ServiceComponent s = new ServiceComponent();
        s.setUuid(UUID.randomUUID());
        s.setGroup("acme");
        s.setName("stock-ticker");
        s.setVersion("1.0.0");
        ServiceComponentIndexer.getInstance().add(s);
        ServiceComponentIndexer.getInstance().commit();
        SearchManager searchManager = new SearchManager();
        ServiceComponentIndexer.getInstance().remove(s);
        ServiceComponentIndexer.getInstance().commit();
        SearchResult result = searchManager.searchIndex(ServiceComponentIndexer.getInstance(), s.getUuid().toString(), 10);
        Assert.assertEquals(1, result.getResults().size());
        Assert.assertEquals(0, result.getResults().get("servicecomponent").size());
    }

    @Test
    public void reindexTest() {
        ServiceComponentIndexer.getInstance().reindex();
    }
}
