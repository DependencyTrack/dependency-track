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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import alpine.event.framework.Event;
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.binder.BaseUnits;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.FileDeleteStrategy;
import org.apache.commons.io.output.NullPrintStream;
import org.apache.commons.lang3.StringUtils;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.CheckIndex;
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
import org.apache.lucene.store.FSDirectory;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.dependencytrack.model.ConfigPropertyConstants.SEARCH_INDEXES_CONSISTENCY_CHECK_DELTA_THRESHOLD;

/**
 * The IndexManager is an abstract class that provides wrappers and convenience methods
 * for managing Lucene indexes.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public abstract class IndexManager implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(IndexManager.class);

    private final Logger logger;
    private final IndexType indexType;
    private final Tag indexTag;
    private final Counter addOperationCounter;
    private final Counter updateOperationCounter;
    private final Counter deleteOperationCounter;
    private final Counter commitOperationCounter;
    private IndexWriter iwriter;
    private DirectoryReader searchReader;
    private Gauge docsRamTotalGauge;
    private Gauge ramBytesUsedGauge;
    private Gauge numDocsGauge;

    /**
     * This methods should be overwritten.
     *
     * @return an array of all fields that can be searched on
     * @since 3.0.0
     */
    public String[] getSearchFields() {
        return new String[]{};
    }

    /**
     * Defines the type of supported indexes.
     *
     * @since 3.0.0
     */
    public enum IndexType {
        PROJECT(Project.class),
        COMPONENT(Component.class),
        SERVICECOMPONENT(ServiceComponent.class),
        VULNERABILITY(Vulnerability.class),
        LICENSE(License.class),
        VULNERABLESOFTWARE(VulnerableSoftware.class);

        final private Class<?> clazz;
        final UUID uuid;

        IndexType(Class<?> clazz) {
            this.clazz = clazz;
            this.uuid = UUID.randomUUID();
        }

        public Class<?> getClazz() {
            return clazz;
        }

        public static Optional<IndexType> getIndexType(String type) {
            try {
                return Optional.of(valueOf(type));
            } catch (Exception e) {
                return Optional.empty();
            }
        }

        public static UUID getUuid(Class<?> clazz) {
            return Arrays.stream(values())
                    .filter(type -> clazz == type.getClazz())
                    .map(type -> type.uuid)
                    .findFirst()
                    .orElse(UUID.randomUUID());
        }
    }

    /**
     * Constructs a new IndexManager. All classes that extend this class should call
     * super(indexType) in their constructor.
     *
     * @param indexType the type of index to use
     * @since 3.0.0
     */
    protected IndexManager(final IndexType indexType) {
        this.logger = Logger.getLogger(getClass());
        this.indexType = indexType;

        this.indexTag = Tag.of("index", indexType.name());
        this.addOperationCounter = Counter.builder("search_index_operations")
                .description("Total number of index operations")
                .tags(Tags.of(indexTag, Tag.of("operation", "add")))
                .baseUnit(BaseUnits.OPERATIONS)
                .register(Metrics.getRegistry());
        this.updateOperationCounter = Counter.builder("search_index_operations")
                .description("Total number of index operations")
                .tags(Tags.of(indexTag, Tag.of("operation", "update")))
                .baseUnit(BaseUnits.OPERATIONS)
                .register(Metrics.getRegistry());
        this.deleteOperationCounter = Counter.builder("search_index_operations")
                .description("Total number of index operations")
                .tags(Tags.of(indexTag, Tag.of("operation", "delete")))
                .baseUnit(BaseUnits.OPERATIONS)
                .register(Metrics.getRegistry());
        this.commitOperationCounter = Counter.builder("search_index_operations")
                .description("Total number of index operations")
                .tags(Tags.of(indexTag, Tag.of("operation", "commit")))
                .baseUnit(BaseUnits.OPERATIONS)
                .register(Metrics.getRegistry());
    }

    /**
     * Returns the index type.
     *
     * @return the index type
     * @since 3.0.0
     */
    public IndexType getIndexType() {
        return indexType;
    }

    /**
     * Retrieves the index directory based on the type of index used.
     *
     * @return a Directory
     * @throws IOException when the directory cannot be accessed
     * @since 3.0.0
     */
    private synchronized Directory getDirectory() throws IOException {
        final File indexDir = getIndexDirectory(indexType);
        if (!indexDir.exists()) {
            if (!indexDir.mkdirs()) {
                logger.error("Unable to create index directory: " + indexDir.getCanonicalPath());
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.FILE_SYSTEM)
                        .title(NotificationConstants.Title.FILE_SYSTEM_ERROR)
                        .content("Unable to create index directory: " + indexDir.getCanonicalPath())
                        .level(NotificationLevel.ERROR)
                );
            }
        }
        return FSDirectory.open(indexDir.toPath());
    }

    /**
     * Opens the index.
     *
     * @throws IOException when the index cannot be opened
     * @since 3.0.0
     */
    protected void openIndex() throws IOException {
        final var analyzer = new StandardAnalyzer();

        final var config = new IndexWriterConfig(analyzer);
        config.setOpenMode(IndexWriterConfig.OpenMode.CREATE_OR_APPEND);
        config.setInfoStream(new LoggingInfoStream(getClass()));
        config.setCommitOnClose(true);

        iwriter = new IndexWriter(getDirectory(), config);

        docsRamTotalGauge = Gauge.builder("search_index_docs_ram_total", iwriter, IndexWriter::numRamDocs)
                .description("Number of documents currently buffered in RAM")
                .tags(Tags.of(indexTag))
                .baseUnit(BaseUnits.OBJECTS)
                .register(Metrics.getRegistry());
        ramBytesUsedGauge = Gauge.builder("search_index_ram_used", iwriter, IndexWriter::ramBytesUsed)
                .description("Memory usage of the index in bytes")
                .tags(Tags.of(indexTag))
                .baseUnit(BaseUnits.BYTES)
                .register(Metrics.getRegistry());
        numDocsGauge = Gauge.builder("search_index_docs_total", iwriter, w -> w.getDocStats().numDocs)
                .description("""
                        Number of docs in this index, including docs not yet flushed (still in the RAM buffer), \
                        and including deletions""")
                .tags(Tags.of(indexTag))
                .baseUnit(BaseUnits.OBJECTS)
                .register(Metrics.getRegistry());
    }

    /**
     * Returns an IndexWriter, by opening the index if necessary.
     *
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

    private void ensureDirectoryReaderOpen() throws IOException {
        if (searchReader == null) {
            searchReader = DirectoryReader.open(getDirectory());
        } else {
            final var changedReader = DirectoryReader.openIfChanged(searchReader);
            if (changedReader != null) {
                searchReader = changedReader;
            }
        }
    }

    /**
     * Returns an {@link IndexSearcher} by opening the index directory first, if necessary.
     *
     * @return an {@link IndexSearcher}
     * @throws IOException when the index directory cannot be opened
     * @since 3.0.0
     */
    protected synchronized IndexSearcher getIndexSearcher() throws IOException {
        ensureDirectoryReaderOpen();
        return new IndexSearcher(searchReader);
    }

    /**
     * Returns a QueryParser.
     *
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

    public void addDocument(final Document document) {
        try {
            getIndexWriter().addDocument(document);
            addOperationCounter.increment();
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            logger.error("An error occurred while adding document to index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.COMPONENT_INDEXER)
                    .content("An error occurred while adding document to index: %s; Check log for details.".formatted(e.getMessage()))
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    public void updateDocument(final Term term, final Document document) {
        try {
            getIndexWriter().updateDocument(term, document);
            updateOperationCounter.increment();
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            logger.error("An error occurred while updating document in index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(getNotificationTitle())
                    .content("An error occurred while updating document in index: %s; Check log for details.".formatted(e.getMessage()))
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    public void deleteDocuments(final Term term) {
        try {
            getIndexWriter().deleteDocuments(term);
            deleteOperationCounter.increment();
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            logger.error("An error occurred while deleting documents from index with term %s".formatted(term), e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(getNotificationTitle())
                    .content("An error occurred while removing a component from index: %s; Check log for details.".formatted(e.getMessage()))
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Commits changes to the index and closes the IndexWriter.
     *
     * @since 3.0.0
     */
    public void commit() {
        try {
            getIndexWriter().commit();
            commitOperationCounter.increment();
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            logger.error("Error committing index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(getNotificationTitle())
                    .content("Error committing index: %s; Check log for details.".formatted(e.getMessage()))
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    protected void handleCorruptIndexException(CorruptIndexException e) {
        LOGGER.error("Corrupted index detected", e);
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.INDEXING_SERVICE)
                .title(getNotificationTitle())
                .content("Corrupted index detected: %s; Check log for details.".formatted(e.getMessage()))
                .level(NotificationLevel.ERROR)
        );
        LOGGER.info("Trying to rebuild the corrupted index " + indexType.name());
        Event.dispatch(new IndexEvent(IndexEvent.Action.REINDEX, indexType.getClazz()));
    }

    /**
     * Closes the IndexWriter.
     *
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
     *
     * @param doc      the Lucene Document to add a field to
     * @param name     the name of the field
     * @param value    the value of the field
     * @param store    storage options
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
     * Retrieves a specific Lucene Document for the specified Object, or null if not found.
     *
     * @param fieldName the name of the field
     * @param uuid      the UUID to retrieve a Document for
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
            handleCorruptIndexException(e);
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
     *
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
     *
     * @since 3.4.0
     */
    public void reindex() {
        try {
            LOGGER.info("Deleting " + indexType.name().toLowerCase() + " index");
            // Cleaner way of purging the index
            // Essentially a call to deleteAll() is equivalent to creating a new IndexWriter with IndexWriterConfig.OpenMode.CREATE
            // It will abort all pending work, trash everything in memory and ensure proper locking on the IndexWriter object
            getIndexWriter().deleteAll();
            getIndexWriter().commit();
        } catch (IOException e) {
            LOGGER.error("An error occurred deleting cleanly the " + indexType.name().toLowerCase() + " index. Forcing delete", e);
            delete(indexType);
        }
    }

    /**
     * Deletes the index directory.
     *
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
     * Ensure that all lucene indexes are healthy.
     */
    public static void ensureIndexesExists() {
        Arrays.stream(IndexManager.IndexType.values()).forEach(indexType -> {
            if (!isIndexHealthy(indexType)) {
                LOGGER.info("(Re)Building index " + indexType.name().toLowerCase());
                LOGGER.debug("Dispatching event to reindex " + indexType.name().toLowerCase());
                Event.dispatch(new IndexEvent(IndexEvent.Action.REINDEX, indexType.getClazz()));
            }
        });
    }

    /**
     * Check that the index exists and is not corrupted
     */
    private static boolean isIndexHealthy(final IndexType indexType) {
        LOGGER.info("Checking the health of index " + indexType.name());
        File indexDirectoryFile = getIndexDirectory(indexType);
        LOGGER.debug("Checking FS directory " + indexDirectoryFile.toPath());
        if (!indexDirectoryFile.exists()) {
            LOGGER.warn("The index " + indexType.name() + " does not exist");
            return false;
        }
        LOGGER.debug("Checking lucene index health");
        Directory luceneIndexDirectory = null;
        CheckIndex checkIndex = null;
        try {
            File writeLock = Path.of(indexDirectoryFile.getAbsolutePath(), IndexWriter.WRITE_LOCK_NAME).toFile();
            if (writeLock.exists()) {
                LOGGER.debug("Stale lock file detected. Deleting it");
                writeLock.delete();
            }
            luceneIndexDirectory = FSDirectory.open(indexDirectoryFile.toPath());
            checkIndex = new CheckIndex(luceneIndexDirectory);
            checkIndex.setFailFast(true);
            if (LOGGER.isDebugEnabled()) {
                checkIndex.setInfoStream(System.out);
            } else {
                checkIndex.setInfoStream(NullPrintStream.INSTANCE);
            }
            CheckIndex.Status status = checkIndex.checkIndex();
            if (status.clean) {
                LOGGER.info("The index " + indexType.name() + " is healthy");
            } else {
                LOGGER.error("The index " + indexType.name().toLowerCase() + " seems to be corrupted");
            }
            return status.clean;
        } catch (IOException | CheckIndex.CheckIndexException e) {
            LOGGER.error("The index " + indexType.name().toLowerCase() + " seems to be corrupted", e);
            return false;
        } finally {
            try {
                if (luceneIndexDirectory != null) {
                    luceneIndexDirectory.close();
                }
                if (checkIndex != null) {
                    checkIndex.close();
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Check that the index exists, is not corrupted and is consistent with the database.
     */
    public static void checkIndexesConsistency() {
        Arrays.stream(IndexType.values()).forEach(indexType -> {
            try (QueryManager qm = new QueryManager()) {
                LOGGER.info("Checking the index " + indexType.name().toLowerCase());
                final ConfigProperty deltaThresholdProperty = qm.getConfigProperty(
                        SEARCH_INDEXES_CONSISTENCY_CHECK_DELTA_THRESHOLD.getGroupName(), SEARCH_INDEXES_CONSISTENCY_CHECK_DELTA_THRESHOLD.getPropertyName());
                double deltaThreshold = Double.parseDouble(deltaThresholdProperty.getPropertyValue());
                double databaseEntityCount = qm.getCount(indexType.getClazz());
                LOGGER.info("Database entity count for type " + indexType.name() + " : " + databaseEntityCount);
                IndexManager indexManager = IndexManagerFactory.getIndexManager(indexType.getClazz());
                indexManager.ensureDirectoryReaderOpen();
                double indexDocumentCount = indexManager.searchReader.numDocs();
                LOGGER.info("Index document count for type " + indexType.name() + " : " + indexDocumentCount);
                double max = Math.max(Math.max(databaseEntityCount, indexDocumentCount), 1);
                double delta = 100 * (Math.abs(databaseEntityCount - indexDocumentCount) / max);
                delta = Math.max(Math.round(delta), 1);
                LOGGER.info("Delta ratio for type " + indexType.name() + " : " + delta + "%");
                if (delta > deltaThreshold) {
                    LOGGER.info("Delta ratio is above the threshold of " + deltaThresholdProperty.getPropertyValue() + "%");
                    LOGGER.debug("Dispatching event to reindex " + indexType.name().toLowerCase());
                    Event.dispatch(new IndexEvent(IndexEvent.Action.REINDEX, indexType.getClazz()));
                }
            } catch (IOException e) {
                LOGGER.error("An I/O exception occurred while trying to read Lucene index", e);
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.INDEXING_SERVICE)
                        .title(NotificationConstants.Title.CORE_INDEXING_SERVICES)
                        .content("An I/O exception occurred while searching Lucene index. Check log for details. " + e.getMessage())
                        .level(NotificationLevel.ERROR)
                );
            }
        });
    }

    private String getNotificationTitle() {
        if (this instanceof ComponentIndexer) {
            return NotificationConstants.Title.COMPONENT_INDEXER;
        } else if (this instanceof LicenseIndexer) {
            return NotificationConstants.Title.LICENSE_INDEXER;
        } else if (this instanceof ProjectIndexer) {
            return NotificationConstants.Title.PROJECT_INDEXER;
        } else if (this instanceof ServiceComponentIndexer) {
            return NotificationConstants.Title.SERVICECOMPONENT_INDEXER;
        } else if (this instanceof VulnerabilityIndexer) {
            return NotificationConstants.Title.VULNERABILITY_INDEXER;
        } else if (this instanceof VulnerableSoftwareIndexer) {
            return NotificationConstants.Title.VULNERABLESOFTWARE_INDEXER;
        }

        throw new IllegalStateException("Unrecognized indexer class %s".formatted(getClass()));
    }

}
