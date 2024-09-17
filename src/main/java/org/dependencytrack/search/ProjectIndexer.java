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
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.search.document.ProjectDocument;

import javax.jdo.Query;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Indexer for operating on projects.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class ProjectIndexer extends IndexManager implements ObjectIndexer<ProjectDocument> {

    private static final Logger LOGGER = Logger.getLogger(ProjectIndexer.class);
    private static final ProjectIndexer INSTANCE = new ProjectIndexer();

    static ProjectIndexer getInstance() {
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
    public void add(final ProjectDocument project) {
        final Document doc = convertToDocument(project);
        addDocument(doc);
    }

    @Override
    public void update(final ProjectDocument project) {
        final Term term = convertToTerm(project);
        final Document doc = convertToDocument(project);
        updateDocument(term, doc);
    }

    /**
     * Deletes a Project object from the Lucene index.
     *
     * @param project A persisted Project object.
     */
    public void remove(final ProjectDocument project) {
        final Term term = convertToTerm(project);
        deleteDocuments(term);
    }

    /**
     * Re-indexes all Project objects.
     * @since 3.4.0
     */
    public void reindex() {
        LOGGER.info("Starting reindex task. This may take some time.");
        super.reindex();

        long docsIndexed = 0;
        final long startTimeNs = System.nanoTime();
        try (final QueryManager qm = new QueryManager()) {
            List<ProjectDocument> docs = fetchNext(qm, null);
            while (!docs.isEmpty()) {
                docs.forEach(this::add);
                docsIndexed += docs.size();
                commit();

                docs = fetchNext(qm, docs.get(docs.size() - 1).id());
            }
        }
        LOGGER.info("Reindexing of %d projects completed in %s"
                .formatted(docsIndexed, Duration.ofNanos(System.nanoTime() - startTimeNs)));
    }

    private static List<ProjectDocument> fetchNext(final QueryManager qm, final Long lastId) {
        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        var filterParts = new ArrayList<String>();
        var params = new HashMap<String, Object>();
        filterParts.add("(active == null || active)");
        if (lastId != null) {
            filterParts.add("id > :lastId");
            params.put("lastId", lastId);
        }
        query.setFilter(String.join(" && ", filterParts));
        query.setNamedParameters(params);
        query.setOrdering("id ASC");
        query.setRange(0, 1000);
        query.setResult("id, uuid, name, version, description");
        try {
            return List.copyOf(query.executeResultList(ProjectDocument.class));
        } finally {
            query.closeAll();
        }
    }

    private Document convertToDocument(final ProjectDocument project) {
        final var doc = new Document();
        addField(doc, IndexConstants.PROJECT_UUID, project.uuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.PROJECT_NAME, project.name(), Field.Store.YES, true);
        addField(doc, IndexConstants.PROJECT_VERSION, project.version(), Field.Store.YES, false);
        addField(doc, IndexConstants.PROJECT_DESCRIPTION, project.description(), Field.Store.YES, true);

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

        return doc;
    }

    private static Term convertToTerm(final ProjectDocument project) {
        return new Term(IndexConstants.PROJECT_UUID, project.uuid().toString());
    }

}
