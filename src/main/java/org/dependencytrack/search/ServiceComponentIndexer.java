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

import alpine.common.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.Term;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.search.document.ServiceComponentDocument;

import javax.jdo.Query;
import java.io.IOException;
import java.time.Duration;
import java.util.List;

/**
 * Indexer for operating on services.
 *
 * @author Steve Springett
 * @since 4.2.0
 */
public final class ServiceComponentIndexer extends IndexManager implements ObjectIndexer<ServiceComponentDocument> {

    private static final Logger LOGGER = Logger.getLogger(ServiceComponentIndexer.class);
    private static final ServiceComponentIndexer INSTANCE = new ServiceComponentIndexer();

    protected static ServiceComponentIndexer getInstance() {
        return INSTANCE;
    }

    /**
     * Private constructor.
     */
    private ServiceComponentIndexer() {
        super(IndexType.SERVICECOMPONENT);
    }

    @Override
    public String[] getSearchFields() {
        return IndexConstants.SERVICECOMPONENT_SEARCH_FIELDS;
    }

    /**
     * Adds a Component object to a Lucene index.
     *
     * @param service A persisted ServiceComponent object.
     */
    public void add(final ServiceComponentDocument service) {
        final Document doc = new Document();
        addField(doc, IndexConstants.SERVICECOMPONENT_UUID, service.uuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.SERVICECOMPONENT_NAME, service.name(), Field.Store.YES, true);
        addField(doc, IndexConstants.SERVICECOMPONENT_GROUP, service.group(), Field.Store.YES, true);
        addField(doc, IndexConstants.SERVICECOMPONENT_VERSION, service.version(), Field.Store.YES, false);
        // TODO: addField(doc, IndexConstants.SERVICECOMPONENT_URL, service.getUrl(), Field.Store.YES, true);
        addField(doc, IndexConstants.SERVICECOMPONENT_DESCRIPTION, service.description(), Field.Store.YES, true);

        try {
            getIndexWriter().addDocument(doc);
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while adding service to index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.SERVICECOMPONENT_INDEXER)
                    .content("An error occurred while adding service to index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Deletes a ServiceComponent object from the Lucene index.
     *
     * @param service A persisted ServiceComponent object.
     */
    public void remove(final ServiceComponentDocument service) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.SERVICECOMPONENT_UUID, service.uuid().toString()));
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while removing a service from the index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.SERVICECOMPONENT_INDEXER)
                    .content("An error occurred while removing a service from the index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Re-indexes all ServiceComponent objects.
     * @since 4.2.0
     */
    public void reindex() {
        LOGGER.info("Starting reindex task. This may take some time.");
        super.reindex();

        long docsIndexed = 0;
        final long startTimeNs = System.nanoTime();
        try (QueryManager qm = new QueryManager()) {
            List<ServiceComponentDocument> docs = fetchNext(qm, null);
            while (!docs.isEmpty()) {
                docs.forEach(this::add);
                docsIndexed += docs.size();
                commit();

                docs = fetchNext(qm, docs.get(docs.size() - 1).id());
            }
        }
        LOGGER.info("Reindexing of %d services completed in %s"
                .formatted(docsIndexed, Duration.ofNanos(System.nanoTime() - startTimeNs)));
    }

    private static List<ServiceComponentDocument> fetchNext(final QueryManager qm, final Long lastId) {
        final Query<ServiceComponent> query = qm.getPersistenceManager().newQuery(ServiceComponent.class);
        if (lastId != null) {
            query.setFilter("id > :lastId");
            query.setParameters(lastId);
        }
        query.setOrdering("id ASC");
        query.setRange(0, 1000);
        query.setResult("id, uuid, \"group\", name, version, description");
        try {
            return List.copyOf(query.executeResultList(ServiceComponentDocument.class));
        } finally {
            query.closeAll();
        }
    }

}
