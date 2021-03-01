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

import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.persistence.PaginatedResult;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.index.Term;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
import java.io.IOException;
import java.util.List;

/**
 * Indexer for operating on services.
 *
 * @author Steve Springett
 * @since 4.2.0
 */
public final class ServiceComponentIndexer extends IndexManager implements ObjectIndexer<ServiceComponent> {

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
    public void add(final ServiceComponent service) {
        final Document doc = new Document();
        addField(doc, IndexConstants.SERVICECOMPONENT_UUID, service.getUuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.SERVICECOMPONENT_NAME, service.getName(), Field.Store.YES, true);
        addField(doc, IndexConstants.SERVICECOMPONENT_GROUP, service.getGroup(), Field.Store.YES, true);
        addField(doc, IndexConstants.SERVICECOMPONENT_VERSION, service.getVersion(), Field.Store.YES, false);
        // TODO: addField(doc, IndexConstants.SERVICECOMPONENT_URL, service.getUrl(), Field.Store.YES, true);
        addField(doc, IndexConstants.SERVICECOMPONENT_DESCRIPTION, service.getDescription(), Field.Store.YES, true);

        try {
            getIndexWriter().addDocument(doc);
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
    public void remove(final ServiceComponent service) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.SERVICECOMPONENT_UUID, service.getUuid().toString()));
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
        try (QueryManager qm = new QueryManager()) {
            final long total = qm.getCount(ServiceComponent.class);
            long count = 0;
            while (count < total) {
                final PaginatedResult result = qm.getServiceComponents();
                final List<ServiceComponent> services = result.getList(ServiceComponent.class);
                for (final ServiceComponent service: services) {
                    add(service);
                }
                count += result.getObjects().size();
                qm.advancePagination();
            }
            commit();
        }
        LOGGER.info("Reindexing complete");
    }
}
