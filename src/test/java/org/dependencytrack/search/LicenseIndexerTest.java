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
import org.dependencytrack.model.License;
import org.dependencytrack.search.document.LicenseDocument;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.awaitility.Awaitility.await;

class LicenseIndexerTest extends PersistenceCapableTest {

    @Test
    void getSearchFieldsTest() {
        String[] fields = LicenseIndexer.getInstance().getSearchFields();
        Assertions.assertEquals(3, fields.length);
        Assertions.assertEquals("uuid", fields[0]);
        Assertions.assertEquals("licenseId", fields[1]);
        Assertions.assertEquals("name", fields[2]);
    }

    @Test
    void getIndexTypeTest() {
        Assertions.assertEquals(IndexManager.IndexType.LICENSE, LicenseIndexer.getInstance().getIndexType());
    }

    @Test
    void addTest() {
        License l = new License();
        l.setUuid(UUID.randomUUID());
        l.setName("Acme License");
        l.setLicenseId("acme-license");
        LicenseIndexer.getInstance().add(new LicenseDocument(l));
        commitIndex();

        await().untilAsserted(() -> {
            SearchResult result = SearchManager.searchIndex(LicenseIndexer.getInstance(), l.getUuid().toString(), 10);
            Assertions.assertEquals(1, result.getResults().size());
            Assertions.assertEquals(1, result.getResults().get("license").size());
        });
    }

    @Test
    void removeTest() {
        License l = new License();
        l.setUuid(UUID.randomUUID());
        l.setName("Acme License");
        l.setLicenseId("acme-license");
        LicenseIndexer.getInstance().add(new LicenseDocument(l));
        commitIndex();
        LicenseIndexer.getInstance().remove(new LicenseDocument(l));
        commitIndex();

        await().untilAsserted(() -> {
            SearchResult result = SearchManager.searchIndex(LicenseIndexer.getInstance(), l.getUuid().toString(), 10);
            Assertions.assertEquals(1, result.getResults().size());
            Assertions.assertEquals(0, result.getResults().get("license").size());
        });
    }

    @Test
    void reindexTest() {
        LicenseIndexer.getInstance().reindex();
    }

    private static void commitIndex() {
        IndexManagerTestUtil.commitIndex(LicenseIndexer.getInstance());
    }
}
