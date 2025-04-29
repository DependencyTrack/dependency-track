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
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.search.document.VulnerableSoftwareDocument;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.awaitility.Awaitility.await;

class VulnerableSoftwareIndexerTest extends PersistenceCapableTest {

    @Test
    void getSearchFieldsTest() {
        String[] fields = VulnerableSoftwareIndexer.getInstance().getSearchFields();
        Assertions.assertEquals(6, fields.length);
        Assertions.assertEquals("uuid", fields[0]);
        Assertions.assertEquals("cpe22", fields[1]);
        Assertions.assertEquals("cpe23", fields[2]);
        Assertions.assertEquals("vendor", fields[3]);
        Assertions.assertEquals("product", fields[4]);
        Assertions.assertEquals("version", fields[5]);
    }

    @Test
    void getIndexTypeTest() {
        Assertions.assertEquals(IndexManager.IndexType.VULNERABLESOFTWARE, VulnerableSoftwareIndexer.getInstance().getIndexType());
    }

    @Test
    void addTest() {
        VulnerableSoftware vulnerableSoftware = new VulnerableSoftware();
        vulnerableSoftware.setUuid(UUID.randomUUID());
        vulnerableSoftware.setCpe22("cpe22");
        vulnerableSoftware.setCpe23("cpe23");
        vulnerableSoftware.setVendor("vendor");
        vulnerableSoftware.setProduct("product");
        vulnerableSoftware.setVersion("version");
        VulnerableSoftwareIndexer.getInstance().add(new VulnerableSoftwareDocument(vulnerableSoftware));
        commitIndex();

        await().untilAsserted(() -> {
            SearchResult result = SearchManager.searchIndex(VulnerableSoftwareIndexer.getInstance(), vulnerableSoftware.getCpe23(), 10);
            Assertions.assertEquals(1, result.getResults().size());
            Assertions.assertEquals(1, result.getResults().get(VulnerableSoftwareIndexer.getInstance().getIndexType().name().toLowerCase()).size());
        });
    }

    @Test
    void removeTest() {
        VulnerableSoftware vulnerableSoftware = new VulnerableSoftware();
        vulnerableSoftware.setUuid(UUID.randomUUID());
        vulnerableSoftware.setCpe22("cpe22");
        vulnerableSoftware.setCpe23("cpe23");
        vulnerableSoftware.setVendor("vendor");
        vulnerableSoftware.setProduct("product");
        vulnerableSoftware.setVersion("version");
        VulnerableSoftwareIndexer.getInstance().add(new VulnerableSoftwareDocument(vulnerableSoftware));
        commitIndex();

        VulnerableSoftwareIndexer.getInstance().remove(new VulnerableSoftwareDocument(vulnerableSoftware));
        commitIndex();

        await().untilAsserted(() -> {
            SearchResult result = SearchManager.searchIndex(VulnerableSoftwareIndexer.getInstance(), vulnerableSoftware.getUuid().toString(), 10);
            Assertions.assertEquals(1, result.getResults().size());
            Assertions.assertEquals(0, result.getResults().get(VulnerableSoftwareIndexer.getInstance().getIndexType().name().toLowerCase()).size());
        });
    }

    @Test
    void reindexTest() {
        VulnerableSoftwareIndexer.getInstance().reindex();
    }

    private static void commitIndex() {
        IndexManagerTestUtil.commitIndex(VulnerableSoftwareIndexer.getInstance());
    }
}
