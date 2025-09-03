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
import org.dependencytrack.model.Component;
import org.dependencytrack.search.document.ComponentDocument;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.awaitility.Awaitility.await;

class ComponentIndexerTest extends PersistenceCapableTest {

    @Test
    void getSearchFieldsTest() {
        String[] fields = ComponentIndexer.getInstance().getSearchFields();
        Assertions.assertEquals(6, fields.length);
        Assertions.assertEquals("uuid", fields[0]);
        Assertions.assertEquals("name", fields[1]);
        Assertions.assertEquals("group", fields[2]);
        Assertions.assertEquals("version", fields[3]);
        Assertions.assertEquals("sha1", fields[4]);
        Assertions.assertEquals("description", fields[5]);
    }

    @Test
    void getIndexTypeTest() {
        Assertions.assertEquals(IndexManager.IndexType.COMPONENT, ComponentIndexer.getInstance().getIndexType());
    }

    @Test
    void addTest() {
        Component c = new Component();
        c.setUuid(UUID.randomUUID());
        c.setGroup("acme");
        c.setName("crypto-library");
        c.setVersion("1.0.0");
        ComponentIndexer.getInstance().add(new ComponentDocument(c));
        commitIndex();

        await().untilAsserted(() -> {
            SearchResult result = SearchManager.searchIndex(ComponentIndexer.getInstance(), c.getUuid().toString(), 10);
            Assertions.assertEquals(1, result.getResults().size());
            Assertions.assertEquals(1, result.getResults().get("component").size());
        });
    }

    @Test
    void removeTest() {
        Component c = new Component();
        c.setUuid(UUID.randomUUID());
        c.setGroup("acme");
        c.setName("crypto-library");
        c.setVersion("1.0.0");
        ComponentIndexer.getInstance().add(new ComponentDocument(c));
        commitIndex();
        ComponentIndexer.getInstance().remove(new ComponentDocument(c));
        commitIndex();

        await().untilAsserted(() -> {
            SearchResult result = SearchManager.searchIndex(ComponentIndexer.getInstance(), c.getUuid().toString(), 10);
            Assertions.assertEquals(1, result.getResults().size());
            Assertions.assertEquals(0, result.getResults().get("component").size());
        });
    }

    @Test
    void reindexTest() {
        ComponentIndexer.getInstance().reindex();
    }

    private static void commitIndex() {
        IndexManagerTestUtil.commitIndex(ComponentIndexer.getInstance());
    }
}
