/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.search;

import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.index.Term;
import org.dependencytrack.model.License;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import java.io.IOException;

/**
 * Indexer for operating on licenses.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class LicenseIndexer extends IndexManager implements ObjectIndexer<License> {

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
    public void add(License license) {
        final Document doc = new Document();
        addField(doc, IndexConstants.LICENSE_UUID, license.getUuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.LICENSE_LICENSEID, license.getLicenseId(), Field.Store.YES, true);
        addField(doc, IndexConstants.LICENSE_NAME, license.getName(), Field.Store.YES, true);

        try {
            getIndexWriter().addDocument(doc);
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
    public void remove(License license) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.LICENSE_UUID, license.getUuid().toString()));
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

}
