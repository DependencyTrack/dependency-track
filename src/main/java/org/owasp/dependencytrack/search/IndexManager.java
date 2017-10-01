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

import alpine.Config;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
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
import org.apache.lucene.util.Version;
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
    private IndexWriter iwriter = null;
    private IndexSearcher isearcher = null;
    private MultiFieldQueryParser qparser = null;
    private IndexType indexType;
    private static final Version VERSION = Version.LUCENE_47;

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
    protected enum IndexType {
        PROJECT,
        COMPONENT,
        VULNERABILITY,
        LICENSE
    }

    /**
     * Constructs a new IndexManager. All classes that extend this class should call
     * super(indexType) in their constructor.
     * @param indexType the type of index to use
     * @since 3.0.0
     */
    protected IndexManager(IndexType indexType) {
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
        final File indexDir = new File(
                Config.getInstance().getDataDirectorty(),
                "index" + File.separator + indexType.name().toLowerCase());
        if (!indexDir.exists()) {
            if (!indexDir.mkdirs()) {
                LOGGER.error("Unable to create index directory: " + indexDir.getCanonicalPath());
            }
        }
        return new SimpleFSDirectory(indexDir);
    }

    /**
     * Opens the index.
     * @throws IOException when the index cannot be opened
     * @since 3.0.0
     */
    protected void openIndex() throws IOException {
        final Analyzer analyzer = new StandardAnalyzer(VERSION);
        final IndexWriterConfig config = new IndexWriterConfig(VERSION, analyzer);
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
        if (iwriter == null) {
            openIndex();
        }
        return iwriter;
    }

    /**
     * Returns an IndexSearcher by opening the index directory first, if necessary.
     * @return an IndexSearcher
     * @throws IOException when the index directory cannot be opened
     * @since 3.0.0
     */
    protected IndexSearcher getIndexSearcher() throws IOException {
        if (isearcher == null) {
            final IndexReader reader = DirectoryReader.open(getDirectory());
            isearcher = new IndexSearcher(reader);
        }
        return isearcher;
    }

    /**
     * Returns a QueryParser.
     * @return a QueryParser
     * @since 3.0.0
     */
    protected QueryParser getQueryParser() {
        final Analyzer analyzer = new StandardAnalyzer(VERSION);
        if (qparser == null) {
            qparser = new MultiFieldQueryParser(VERSION, getSearchFields(), analyzer, IndexConstants.getBoostMap());
            qparser.setAllowLeadingWildcard(true);
        }
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
            LOGGER.error("Error committing index");
            LOGGER.error(e.getMessage());
        }
    }

    /**
     * Closes the IndexWriter.
     * @since 3.0.0
     */
    public void close() {
        if (iwriter != null) {
            try {
                iwriter.close();
            } catch (IOException e) {
                // do nothing...
            }
        }
    }

    /**
     * Upon finalization, closes if not already closed.
     * @throws Throwable the {@code Exception} raised by this method
     * @since 3.0.0
     */
    protected void finalize() throws Throwable {
        close();
        super.finalize();
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
    protected void addField(Document doc, String name, String value, Field.Store store, boolean tokenize) {
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
    protected void updateField(Document doc, String name, String value) {
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
    protected Document getDocument(String fieldName, String uuid) {
        final List<Document> list = new ArrayList<>();
        try {
            final TermQuery query = new TermQuery(new Term(fieldName, uuid));
            final TopDocs results = getIndexSearcher().search(query, 1000000);
            final ScoreDoc[] hits = results.scoreDocs;
            for (ScoreDoc hit : hits) {
                list.add(getIndexSearcher().doc(hit.doc));
            }
        } catch (CorruptIndexException e) {
            LOGGER.error("Corrupted Lucene Index Detected");
            LOGGER.error(e.getMessage());
        } catch (IOException e) {
            LOGGER.error("IO Exception searching Lucene Index");
            LOGGER.error(e.getMessage());
        }
        if (list.size() > 0) {
            return list.get(0); // There should only be one document
        } else {
            return null;
        }
    }

}
