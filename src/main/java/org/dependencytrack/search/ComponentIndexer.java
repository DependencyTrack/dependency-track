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
import org.dependencytrack.model.Component;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;

import java.io.IOException;

/**
 * Indexer for operating on components.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class ComponentIndexer extends IndexManager implements ObjectIndexer<Component> {

    private static final Logger LOGGER = Logger.getLogger(ComponentIndexer.class);
    private static final ComponentIndexer INSTANCE = new ComponentIndexer();

    protected static ComponentIndexer getInstance() {
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
    public void add(Component component) {
        final Document doc = new Document();
        addField(doc, IndexConstants.COMPONENT_UUID, component.getUuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.COMPONENT_NAME, component.getName(), Field.Store.YES, true);
        addField(doc, IndexConstants.COMPONENT_GROUP, component.getGroup(), Field.Store.YES, true);
        addField(doc, IndexConstants.COMPONENT_VERSION, component.getVersion(), Field.Store.YES, false);
        addField(doc, IndexConstants.COMPONENT_SHA1, component.getSha1(), Field.Store.YES, true);
        addField(doc, IndexConstants.COMPONENT_DESCRIPTION, component.getDescription(), Field.Store.YES, true);

        try {
            getIndexWriter().addDocument(doc);
        } catch (IOException e) {
            LOGGER.error("An error occurred while adding component to index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.COMPONENT_INDEXER)
                    .content("An error occurred while adding component to index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Deletes a Component object from the Lucene index.
     *
     * @param component A persisted Component object.
     */
    public void remove(Component component) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.COMPONENT_UUID, component.getUuid().toString()));
        } catch (IOException e) {
            LOGGER.error("An error occurred while removing a component from the index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.COMPONENT_INDEXER)
                    .content("An error occurred while removing a component from the index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

}
