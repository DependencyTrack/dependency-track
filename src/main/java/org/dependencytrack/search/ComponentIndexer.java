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

import alpine.common.logging.Logger;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.index.Term;
import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.search.document.ComponentDocument;

import javax.jdo.Query;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Indexer for operating on components.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class ComponentIndexer extends IndexManager implements ObjectIndexer<ComponentDocument> {

    private static final Logger LOGGER = Logger.getLogger(ComponentIndexer.class);
    private static final ComponentIndexer INSTANCE = new ComponentIndexer();

    static ComponentIndexer getInstance() {
        return INSTANCE;
    }

    /**
     * Private constructor.
     */
    private ComponentIndexer() {
        super(IndexType.COMPONENT);
    }

    @Override
    public String[] getSearchFields() {
        return IndexConstants.COMPONENT_SEARCH_FIELDS;
    }

    /**
     * Adds a Component object to a Lucene index.
     *
     * @param component A persisted Component object.
     */
    public void add(final ComponentDocument component) {
        final Document doc = convertToDocument(component);
        addDocument(doc);
    }

    @Override
    public void update(ComponentDocument component) {
        final Term term = convertToTerm(component);
        final Document doc = convertToDocument(component);
        updateDocument(term, doc);
    }

    /**
     * Deletes a Component object from the Lucene index.
     *
     * @param component A persisted Component object.
     */
    public void remove(final ComponentDocument component) {
        final Term term = convertToTerm(component);
        deleteDocuments(term);
    }

    /**
     * Re-indexes all Component objects.
     * @since 3.4.0
     */
    public void reindex() {
        LOGGER.info("Starting reindex task. This may take some time.");
        super.reindex();

        long docsIndexed = 0;
        final long startTimeNs = System.nanoTime();
        try (final QueryManager qm = new QueryManager()) {
            List<ComponentDocument> docs = fetchNext(qm, null);
            while (!docs.isEmpty()) {
                docs.forEach(this::add);
                docsIndexed += docs.size();
                commit();

                docs = fetchNext(qm, docs.get(docs.size() - 1).id());
            }
        }
        LOGGER.info("Reindexing of %d components completed in %s"
                .formatted(docsIndexed, Duration.ofNanos(System.nanoTime() - startTimeNs)));
    }

    private static List<ComponentDocument> fetchNext(final QueryManager qm, final Long lastId) {
        final Query<Component> query = qm.getPersistenceManager().newQuery(Component.class);
        var filterParts = new ArrayList<String>();
        var params = new HashMap<String, Object>();
        filterParts.add("(project.active == null || project.active)");
        if (lastId != null) {
            filterParts.add("id > :lastId");
            params.put("lastId", lastId);
        }
        query.setFilter(String.join(" && ", filterParts));
        query.setNamedParameters(params);
        query.setOrdering("id ASC");
        query.setRange(0, 1000);
        query.setResult("id, uuid, \"group\", name, version, description, sha1");
        try {
            return List.copyOf(query.executeResultList(ComponentDocument.class));
        } finally {
            query.closeAll();
        }
    }

    private Document convertToDocument(final ComponentDocument component) {
        final var doc = new Document();
        addField(doc, IndexConstants.COMPONENT_UUID, component.uuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.COMPONENT_NAME, component.name(), Field.Store.YES, true);
        addField(doc, IndexConstants.COMPONENT_GROUP, component.group(), Field.Store.YES, true);
        addField(doc, IndexConstants.COMPONENT_VERSION, component.version(), Field.Store.YES, false);
        addField(doc, IndexConstants.COMPONENT_SHA1, component.sha1(), Field.Store.YES, true);
        addField(doc, IndexConstants.COMPONENT_DESCRIPTION, component.description(), Field.Store.YES, true);
        return doc;
    }

    private static Term convertToTerm(final ComponentDocument component) {
        return new Term(IndexConstants.COMPONENT_UUID, component.uuid().toString());
    }

}
