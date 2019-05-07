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
import org.dependencytrack.model.License;
import org.junit.Assert;
import org.junit.Test;
import java.util.UUID;

public class LicenseIndexerTest extends PersistenceCapableTest {

    @Test
    public void getSearchFieldsTest() {
        String[] fields = LicenseIndexer.getInstance().getSearchFields();
        Assert.assertEquals(3, fields.length);
        Assert.assertEquals("uuid", fields[0]);
        Assert.assertEquals("licenseId", fields[1]);
        Assert.assertEquals("name", fields[2]);
    }

    @Test
    public void getIndexTypeTest() {
        Assert.assertEquals(IndexManager.IndexType.LICENSE, LicenseIndexer.getInstance().getIndexType());
    }

    @Test
    public void addTest() {
        License l = new License();
        l.setUuid(UUID.randomUUID());
        l.setName("Acme License");
        l.setLicenseId("acme-license");
        LicenseIndexer.getInstance().add(l);
        LicenseIndexer.getInstance().commit();
        SearchManager searchManager = new SearchManager();
        SearchResult result = searchManager.searchIndex(LicenseIndexer.getInstance(), l.getUuid().toString(), 10);
        Assert.assertEquals(1, result.getResults().size());
        Assert.assertEquals(1, result.getResults().get("license").size());
    }

    @Test
    public void removeTest() {
        License l = new License();
        l.setUuid(UUID.randomUUID());
        l.setName("Acme License");
        l.setLicenseId("acme-license");
        LicenseIndexer.getInstance().add(l);
        LicenseIndexer.getInstance().commit();
        SearchManager searchManager = new SearchManager();
        LicenseIndexer.getInstance().remove(l);
        LicenseIndexer.getInstance().commit();
        SearchResult result = searchManager.searchIndex(LicenseIndexer.getInstance(), l.getUuid().toString(), 10);
        Assert.assertEquals(1, result.getResults().size());
        Assert.assertEquals(0, result.getResults().get("license").size());
    }

    @Test
    public void reindexTest() {
        LicenseIndexer.getInstance().reindex();
    }
}
