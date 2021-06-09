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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
import java.io.IOException;
import java.util.List;

/**
 * Indexer for operating on projects.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class ProjectIndexer extends IndexManager implements ObjectIndexer<Project> {

    private static final Logger LOGGER = Logger.getLogger(ProjectIndexer.class);
    private static final ProjectIndexer INSTANCE = new ProjectIndexer();

    protected static ProjectIndexer getInstance() {
        return INSTANCE;
    }

    /**
     * Private constructor.
     */
    private ProjectIndexer() {
        super(IndexType.PROJECT);
    }

    @Override
    public String[] getSearchFields() {
        return IndexConstants.PROJECT_SEARCH_FIELDS;
    }

    /**
     * Adds a Project object to a Lucene index.
     *
     * @param project A persisted Project object.
     */
    public void add(final Project project) {
        final Document doc = new Document();
        addField(doc, IndexConstants.PROJECT_UUID, project.getUuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.PROJECT_NAME, project.getName(), Field.Store.YES, true);
        addField(doc, IndexConstants.PROJECT_VERSION, project.getVersion(), Field.Store.YES, false);
        addField(doc, IndexConstants.PROJECT_DESCRIPTION, project.getDescription(), Field.Store.YES, true);

        /*
        // There's going to potentially be confidential information in the project properties. Do not index.

        final StringBuilder sb = new StringBuilder();
        if (project.getProperties() != null) {
            for (ProjectProperty property : project.getProperties()) {
                sb.append(property.getPropertyValue()).append(" ");
            }
        }

        addField(doc, IndexConstants.PROJECT_PROPERTIES, sb.toString().trim(), Field.Store.YES, true);
        */

        try {
            getIndexWriter().addDocument(doc);
        } catch (IOException e) {
            LOGGER.error("An error occurred while adding a project to the index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.PROJECT_INDEXER)
                    .content("An error occurred while adding a project to the index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Deletes a Project object from the Lucene index.
     *
     * @param project A persisted Project object.
     */
    public void remove(final Project project) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.PROJECT_UUID, project.getUuid().toString()));
        } catch (IOException e) {
            LOGGER.error("An error occurred while removing a project from the index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.PROJECT_INDEXER)
                    .content("An error occurred while removing a project from the index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Re-indexes all Project objects.
     * @since 3.4.0
     */
    public void reindex() {
        LOGGER.info("Starting reindex task. This may take some time.");
        super.reindex();
        try (final QueryManager qm = new QueryManager()) {
            final PaginatedResult result = qm.getProjects(false, true);
            long count = 0;
            boolean shouldContinue = true;
            while (count < result.getTotal() && shouldContinue) {
                for (final Project project: result.getList(Project.class)) {
                    add(project);
                }
                int lastResult = result.getObjects().size();
                count += lastResult;
                shouldContinue = lastResult > 0;
                qm.advancePagination();
            }
            commit();
        }
        LOGGER.info("Reindexing complete");
    }
}
