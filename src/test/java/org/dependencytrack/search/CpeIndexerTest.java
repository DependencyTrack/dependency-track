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
import org.dependencytrack.model.Cpe;
import org.junit.Assert;
import org.junit.Test;

import java.util.UUID;

public class CpeIndexerTest extends PersistenceCapableTest {

    @Test
    public void getSearchFieldsTest() {
        String[] fields = CpeIndexer.getInstance().getSearchFields();
        Assert.assertEquals(6, fields.length);
        Assert.assertEquals("uuid", fields[0]);
        Assert.assertEquals("cpe22", fields[1]);
        Assert.assertEquals("cpe23", fields[2]);
        Assert.assertEquals("vendor", fields[3]);
        Assert.assertEquals("product", fields[4]);
        Assert.assertEquals("version", fields[5]);
    }

    @Test
    public void getIndexTypeTest() {
        Assert.assertEquals(IndexManager.IndexType.CPE, CpeIndexer.getInstance().getIndexType());
    }

    @Test
    public void addTest() {
        Cpe cpe = new Cpe();
        cpe.setUuid(UUID.randomUUID());
        cpe.setCpe22("cpe22");
        cpe.setCpe23("cpe23");
        cpe.setVendor("vendor");
        cpe.setProduct("product");
        cpe.setVersion("version");
        CpeIndexer.getInstance().add(cpe);
        CpeIndexer.getInstance().commit();
        SearchManager searchManager = new SearchManager();
        SearchResult result = searchManager.searchIndex(CpeIndexer.getInstance(), cpe.getCpe23(), 10);
        Assert.assertEquals(1, result.getResults().size());
        Assert.assertEquals(1, result.getResults().get(CpeIndexer.getInstance().getIndexType().name().toLowerCase()).size());
    }

    @Test
    public void removeTest() {
        Cpe cpe = new Cpe();
        cpe.setUuid(UUID.randomUUID());
        cpe.setCpe22("cpe22");
        cpe.setCpe23("cpe23");
        cpe.setVendor("vendor");
        cpe.setProduct("product");
        cpe.setVersion("version");
        CpeIndexer.getInstance().add(cpe);
        CpeIndexer.getInstance().commit();
        SearchManager searchManager = new SearchManager();
        CpeIndexer.getInstance().remove(cpe);
        CpeIndexer.getInstance().commit();
        SearchResult result = searchManager.searchIndex(CpeIndexer.getInstance(), cpe.getUuid().toString(), 10);
        Assert.assertEquals(1, result.getResults().size());
        Assert.assertEquals(0, result.getResults().get(CpeIndexer.getInstance().getIndexType().name().toLowerCase()).size());
    }

    @Test
    public void reindexTest() {
        CpeIndexer.getInstance().reindex();
    }
}
