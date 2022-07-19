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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.FileDeleteStrategy;
import org.apache.commons.lang3.StringUtils;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.Term;
import org.apache.lucene.queryparser.classic.MultiFieldQueryParser;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TermQuery;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.SimpleFSDirectory;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * The IndexManager is an abstract class that provides wrappers and convenience methods
 * for managing Lucene indexes.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public abstract class IndexManager implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(IndexManager.class);
    private IndexWriter iwriter;
    private DirectoryReader searchReader;
    private final IndexType indexType;

    /**
     * This methods should be overwritten.
     * @return an array of all fields that can be searched on
     * @since 3.0.0
     */
    public String[] getSearchFields() {
        return new String[]{};
    }

    /**
     * Defines the type of supported indexes.
     * @since 3.0.0
     */
    public enum IndexType {
        PROJECT,
        COMPONENT,
        SERVICECOMPONENT,
        VULNERABILITY,
        LICENSE,
        CPE,
        VULNERABLESOFTWARE,
    }

    /**
     * Constructs a new IndexManager. All classes that extend this class should call
     * super(indexType) in their constructor.
     * @param indexType the type of index to use
     * @since 3.0.0
     */
    protected IndexManager(final IndexType indexType) {
        this.indexType = indexType;
    }

    /**
     * Returns the index type.
     * @return the index type
     * @since 3.0.0
     */
    protected IndexType getIndexType() {
        return indexType;
    }

    /**
     * Retrieves the index directory based on the type of index used.
     * @return a Directory
     * @throws IOException when the directory cannot be accessed
     * @since 3.0.0
     */
    private synchronized Directory getDirectory() throws IOException {
        final File indexDir = getIndexDirectory(indexType);
        if (!indexDir.exists()) {
            if (!indexDir.mkdirs()) {
                LOGGER.error("Unable to create index directory: " + indexDir.getCanonicalPath());
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.FILE_SYSTEM)
                        .title(NotificationConstants.Title.FILE_SYSTEM_ERROR)
                        .content("Unable to create index directory: " + indexDir.getCanonicalPath())
                        .level(NotificationLevel.ERROR)
                );
            }
        }
        return new SimpleFSDirectory(indexDir.toPath());
    }

    /**
     * Opens the index.
     * @throws IOException when the index cannot be opened
     * @since 3.0.0
     */
    protected void openIndex() throws IOException {
        final Analyzer analyzer = new StandardAnalyzer();
        final IndexWriterConfig config = new IndexWriterConfig(analyzer);
        config.setOpenMode(IndexWriterConfig.OpenMode.CREATE_OR_APPEND);
        iwriter = new IndexWriter(getDirectory(), config);
    }

    /**
     * Returns an IndexWriter, by opening the index if necessary.
     * @return an IndexWriter
     * @throws IOException when the index cannot be opened
     * @since 3.0.0
     */
    protected IndexWriter getIndexWriter() throws IOException {
        if (iwriter == null || !iwriter.isOpen()) {
            openIndex();
        }
        return iwriter;
    }

    /**
     * Returns an {@link IndexSearcher} by opening the index directory first, if necessary.
     *
     * @return an {@link IndexSearcher}
     * @throws IOException when the index directory cannot be opened
     * @since 3.0.0
     */
    protected synchronized IndexSearcher getIndexSearcher() throws IOException {
        if (searchReader == null) {
            searchReader = DirectoryReader.open(getDirectory());
        } else {
            final var changedReader = DirectoryReader.openIfChanged(searchReader);
            if (changedReader != null) {
                searchReader = changedReader;
            }
        }
        return new IndexSearcher(searchReader);
    }

    /**
     * Returns a QueryParser.
     * @return a QueryParser
     * @since 3.0.0
     */
    protected QueryParser getQueryParser() {
        // DO NOT close (either manually or try-with-resource) the Analyzer
        final Analyzer analyzer = new StandardAnalyzer();
        MultiFieldQueryParser qparser = new MultiFieldQueryParser(getSearchFields(), analyzer, IndexConstants.getBoostMap());
        qparser.setAllowLeadingWildcard(true);
        return qparser;
    }

    /**
     * Commits changes to the index and closes the IndexWriter.
     * @since 3.0.0
     */
    public void commit() {
        try {
            getIndexWriter().commit();
        } catch (IOException e) {
            LOGGER.error("Error committing index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.CORE_INDEXING_SERVICES)
                    .content("Error committing index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Closes the IndexWriter.
     * @since 3.0.0
     */
    public void close() {
        if (iwriter != null) {
            try {
                if (iwriter.isOpen()) {
                    iwriter.close();
                }
            } catch (IOException e) {
                // do nothing...
            }
        }
    }

    /**
     * Adds a Field to a Document.
     * @param doc the Lucene Document to add a field to
     * @param name the name of the field
     * @param value the value of the field
     * @param store storage options
     * @param tokenize specifies if the field should be tokenized or not
     * @since 3.0.0
     */
    protected void addField(final Document doc, final String name, String value, final Field.Store store, final boolean tokenize) {
        if (StringUtils.isBlank(value)) {
            value = "";
        }
        final Field field;
        if (tokenize) {
            field = new TextField(name, value, store);
        } else {
            field = new StringField(name, value, store);
        }
        doc.add(field);
    }

    /**
     * Updates a Field in a Document.
     * @param doc the Lucene Document to update the field in
     * @param name the name of the field
     * @param value the value of the field
     * @since 3.0.0
     */
    protected void updateField(final Document doc, final String name, String value) {
        if (StringUtils.isBlank(value)) {
            value = "";
        }
        final Field field = (Field) doc.getField(name);
        field.setStringValue(value);
    }

    /**
     * Retrieves a specific Lucene Document for the specified Object, or null if not found.
     * @param fieldName the name of the field
     * @param uuid the UUID to retrieve a Document for
     * @return a Lucene Document
     * @since 3.0.0
     */
    protected Document getDocument(final String fieldName, final String uuid) {
        final List<Document> list = new ArrayList<>();
        try {
            final TermQuery query = new TermQuery(new Term(fieldName, uuid));
            final TopDocs results = getIndexSearcher().search(query, 1000000);
            final ScoreDoc[] hits = results.scoreDocs;
            for (final ScoreDoc hit : hits) {
                list.add(getIndexSearcher().doc(hit.doc));
            }
        } catch (CorruptIndexException e) {
            LOGGER.error("Corrupted Lucene index detected", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.CORE_INDEXING_SERVICES)
                    .content("Corrupted Lucene index detected. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        } catch (IOException e) {
            LOGGER.error("An I/O exception occurred while searching Lucene index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.CORE_INDEXING_SERVICES)
                    .content("An I/O exception occurred while searching Lucene index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
        if (CollectionUtils.isNotEmpty(list)) {
            return list.get(0); // There should only be one document
        } else {
            return null;
        }
    }

    /**
     * Returns the directory where this index is located.
     * @return a File object
     * @since 3.4.0
     */
    private static File getIndexDirectory(final IndexType indexType) {
        return new File(
                Config.getInstance().getDataDirectorty(),
                "index" + File.separator + indexType.name().toLowerCase());
    }

    /**
     * Deletes the index directory. This method should be both overwritten and called via overwriting method.
     * @since 3.4.0
     */
    public void reindex() {
        delete(indexType);
    }

    /**
     * Deletes the index directory.
     * @since 3.4.0
     */
    public static void delete(final IndexType indexType) {
        final File indexDir = getIndexDirectory(indexType);
        if (indexDir.exists()) {
            LOGGER.info("Deleting " + indexType.name().toLowerCase() + " index");
            try {
                FileDeleteStrategy.FORCE.delete(indexDir);
            } catch (IOException e) {
                LOGGER.error("An error occurred deleting the " + indexType.name().toLowerCase() + " index", e);
            }
        }
    }

    /**
     * Returns if the index directory exists or not.
     * @since 3.4.0
     */
    public static boolean exists(final IndexType indexType) {
        return getIndexDirectory(indexType).exists();
    }
}
