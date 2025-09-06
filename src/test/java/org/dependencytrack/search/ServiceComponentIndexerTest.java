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
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.search.document.ServiceComponentDocument;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.awaitility.Awaitility.await;

class ServiceComponentIndexerTest extends PersistenceCapableTest {

    @Test
    void getSearchFieldsTest() {
        String[] fields = ServiceComponentIndexer.getInstance().getSearchFields();
        Assertions.assertEquals(6, fields.length);
        Assertions.assertEquals("uuid", fields[0]);
        Assertions.assertEquals("name", fields[1]);
        Assertions.assertEquals("group", fields[2]);
        Assertions.assertEquals("version", fields[3]);
        Assertions.assertEquals("url", fields[4]);
        Assertions.assertEquals("description", fields[5]);
    }

    @Test
    void getIndexTypeTest() {
        Assertions.assertEquals(IndexManager.IndexType.SERVICECOMPONENT, ServiceComponentIndexer.getInstance().getIndexType());
    }

    @Test
    void addTest() {
        ServiceComponent s = new ServiceComponent();
        s.setUuid(UUID.randomUUID());
        s.setGroup("acme");
        s.setName("stock-ticker");
        s.setVersion("1.0.0");
        ServiceComponentIndexer.getInstance().add(new ServiceComponentDocument(s));
        commitIndex();

        await().untilAsserted(() -> {
            SearchResult result = SearchManager.searchIndex(ServiceComponentIndexer.getInstance(), s.getUuid().toString(), 10);
            Assertions.assertEquals(1, result.getResults().size());
            Assertions.assertEquals(1, result.getResults().get("servicecomponent").size());
        });
    }

    @Test
    void removeTest() {
        ServiceComponent s = new ServiceComponent();
        s.setUuid(UUID.randomUUID());
        s.setGroup("acme");
        s.setName("stock-ticker");
        s.setVersion("1.0.0");
        ServiceComponentIndexer.getInstance().add(new ServiceComponentDocument(s));
        commitIndex();
        ServiceComponentIndexer.getInstance().remove(new ServiceComponentDocument(s));
        commitIndex();

        await().untilAsserted(() -> {
            SearchResult result = SearchManager.searchIndex(ServiceComponentIndexer.getInstance(), s.getUuid().toString(), 10);
            Assertions.assertEquals(1, result.getResults().size());
            Assertions.assertEquals(0, result.getResults().get("servicecomponent").size());
        });
    }

    @Test
    void reindexTest() {
        ServiceComponentIndexer.getInstance().reindex();
    }

    private static void commitIndex() {
        IndexManagerTestUtil.commitIndex(ServiceComponentIndexer.getInstance());
    }
}
