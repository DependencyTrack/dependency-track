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
import org.dependencytrack.model.Cpe;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
import java.io.IOException;
import java.util.List;

/**
 * Indexer for operating on CPEs.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public final class CpeIndexer extends IndexManager implements ObjectIndexer<Cpe> {

    private static final Logger LOGGER = Logger.getLogger(CpeIndexer.class);
    private static final CpeIndexer INSTANCE = new CpeIndexer();

    protected static CpeIndexer getInstance() {
        return INSTANCE;
    }

    /**
     * Private constructor.
     */
    private CpeIndexer() {
        super(IndexType.CPE);
    }

    @Override
    public String[] getSearchFields() {
        return IndexConstants.CPE_SEARCH_FIELDS;
    }

    /**
     * Adds a Cpe object to a Lucene index.
     *
     * @param cpe A persisted Cpe object.
     */
    public void add(final Cpe cpe) {
        final Document doc = new Document();
        addField(doc, IndexConstants.CPE_UUID, cpe.getUuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.CPE_22, cpe.getCpe22(), Field.Store.YES, true);
        addField(doc, IndexConstants.CPE_23, cpe.getCpe23(), Field.Store.YES, true);
        addField(doc, IndexConstants.CPE_VENDOR, cpe.getVendor(), Field.Store.YES, true);
        addField(doc, IndexConstants.CPE_PRODUCT, cpe.getProduct(), Field.Store.YES, true);
        addField(doc, IndexConstants.CPE_VERSION, cpe.getVersion(), Field.Store.YES, true);

        try {
            getIndexWriter().addDocument(doc);
        } catch (IOException e) {
            LOGGER.error("An error occurred while adding a CPE to the index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.CPE_INDEXER)
                    .content("An error occurred while adding a CPE to the index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Deletes a Cpe object from the Lucene index.
     *
     * @param cpe A persisted Cpe object.
     */
    public void remove(final Cpe cpe) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.CPE_UUID, cpe.getUuid().toString()));
        } catch (IOException e) {
            LOGGER.error("An error occurred while removing a CPE from the index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.CPE_INDEXER)
                    .content("An error occurred while removing a CPE from the index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Re-indexes all CPE objects.
     */
    public void reindex() {
        LOGGER.info("Starting reindex task. This may take some time.");
        super.reindex();
        try (QueryManager qm = new QueryManager()) {
            final long total = qm.getCount(Cpe.class);
            long count = 0;
            while (count < total) {
                final PaginatedResult result = qm.getCpes();
                final List<Cpe> cpes = result.getList(Cpe.class);
                for (final Cpe cpe: cpes) {
                    add(cpe);
                }
                count += result.getObjects().size();
                qm.advancePagination();
            }
            commit();
        }
        LOGGER.info("Reindexing complete");
    }
}
