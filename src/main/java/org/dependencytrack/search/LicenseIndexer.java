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
import org.dependencytrack.model.License;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.search.document.LicenseDocument;

import javax.jdo.Query;
import java.io.IOException;
import java.time.Duration;
import java.util.List;

/**
 * Indexer for operating on licenses.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class LicenseIndexer extends IndexManager implements ObjectIndexer<LicenseDocument> {

    private static final Logger LOGGER = Logger.getLogger(LicenseIndexer.class);
    private static final LicenseIndexer INSTANCE = new LicenseIndexer();

    protected static LicenseIndexer getInstance() {
        return INSTANCE;
    }

    /**
     * Private constructor.
     */
    private LicenseIndexer() {
        super(IndexType.LICENSE);
    }

    @Override
    public String[] getSearchFields() {
        return IndexConstants.LICENSE_SEARCH_FIELDS;
    }

    /**
     * Adds a License object to a Lucene index.
     *
     * @param license A persisted License object.
     */
    public void add(final LicenseDocument license) {
        final Document doc = new Document();
        addField(doc, IndexConstants.LICENSE_UUID, license.uuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.LICENSE_LICENSEID, license.licenseId(), Field.Store.YES, true);
        addField(doc, IndexConstants.LICENSE_NAME, license.name(), Field.Store.YES, true);

        try {
            getIndexWriter().addDocument(doc);
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while adding a license to the index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.LICENSE_INDEXER)
                    .content("An error occurred while adding a license to the index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Deletes a License object from the Lucene index.
     *
     * @param license A persisted License object.
     */
    public void remove(final LicenseDocument license) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.LICENSE_UUID, license.uuid().toString()));
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while removing a license from the index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.LICENSE_INDEXER)
                    .content("An error occurred while removing a license from the index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Re-indexes all License objects.
     * @since 3.4.0
     */
    public void reindex() {
        LOGGER.info("Starting reindex task. This may take some time.");
        super.reindex();

        long docsIndexed = 0;
        final long startTimeNs = System.nanoTime();
        try (QueryManager qm = new QueryManager()) {
            List<LicenseDocument> docs = fetchNext(qm, null);
            while (!docs.isEmpty()) {
                docs.forEach(this::add);
                docsIndexed += docs.size();
                commit();

                docs = fetchNext(qm, docs.get(docs.size() - 1).id());
            }
        }
        LOGGER.info("Reindexing of %d licenses completed in %s"
                .formatted(docsIndexed, Duration.ofNanos(System.nanoTime() - startTimeNs)));
    }

    private static List<LicenseDocument> fetchNext(final QueryManager qm, final Long lastId) {
        final Query<License> query = qm.getPersistenceManager().newQuery(License.class);
        if (lastId != null) {
            query.setFilter("id > :lastId");
            query.setParameters(lastId);
        }
        query.setOrdering("id ASC");
        query.setRange(0, 1000);
        query.setResult("id, uuid, licenseId, name");
        try {
            return List.copyOf(query.executeResultList(LicenseDocument.class));
        } finally {
            query.closeAll();
        }
    }

}
