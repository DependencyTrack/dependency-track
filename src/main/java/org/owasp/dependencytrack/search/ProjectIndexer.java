/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.search;

import org.apache.log4j.Logger;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.index.Term;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.ProjectProperty;
import java.io.IOException;

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
    public void add(Project project) {
        final Document doc = new Document();
        addField(doc, IndexConstants.PROJECT_UUID, project.getUuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.PROJECT_NAME, project.getName(), Field.Store.YES, true);
        addField(doc, IndexConstants.PROJECT_VERSION, project.getVersion(), Field.Store.YES, false);
        addField(doc, IndexConstants.PROJECT_DESCRIPTION, project.getDescription(), Field.Store.YES, true);

        final StringBuilder sb = new StringBuilder();
        if (project.getProperties() != null) {
            for (ProjectProperty property : project.getProperties()) {
                sb.append(property.getValue()).append(" ");
            }
        }
        addField(doc, IndexConstants.PROJECT_PROPERTIES, sb.toString().trim(), Field.Store.YES, true);

        try {
            getIndexWriter().addDocument(doc);
        } catch (IOException e) {
            LOGGER.error("Error adding object to index");
            LOGGER.error(e.getMessage());
        }
    }

    /**
     * Deletes a Project object from the Lucene index.
     *
     * @param project A persisted Project object.
     */
    public void remove(Project project) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.PROJECT_UUID, project.getUuid().toString()));
        } catch (IOException e) {
            LOGGER.error("Error removing object from index");
            LOGGER.error(e.getMessage());
        }
    }

}
