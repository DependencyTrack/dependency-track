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
import org.apache.commons.lang3.StringUtils;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.IndexableField;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopDocs;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Performs search operations on an index.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class SearchManager {

    private static final Logger LOGGER = Logger.getLogger(SearchManager.class);

    public SearchResult searchIndices(final String queryString, final int limit) {
        final SearchResult searchResult = new SearchResult();
        final IndexManager[] indexManagers = {
                ProjectIndexer.getInstance(),
                ComponentIndexer.getInstance(),
                ServiceComponentIndexer.getInstance(),
                VulnerabilityIndexer.getInstance(),
                LicenseIndexer.getInstance()
        };
        Stream.of(indexManagers).parallel().forEach(
                indexManager -> {
                    final SearchResult individualResult = searchIndex(indexManager, queryString, limit);
                    searchResult.getResults().putAll(individualResult.getResults());
                }
        );
        return searchResult;
    }

    public SearchResult searchIndex(final IndexManager indexManager, final String queryString, final int limit) {
        final SearchResult searchResult = new SearchResult();
        final List<Map<String, String>> resultSet = new ArrayList<>();
        try {
            String escaped = escape(queryString);
            final String sb = escaped +
                    "^100" +
                    " OR " +
                    escaped +
                    "*" +
                    "^5" +
                    " OR " +
                    "*" +
                    escaped +
                    "*";
            final Query query = indexManager.getQueryParser().parse(sb);
            final TopDocs results = indexManager.getIndexSearcher().search(query, limit);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Searching for: " + escaped + " - Total Hits: " + results.totalHits);
            }

            for (final ScoreDoc scoreDoc: results.scoreDocs) {
                final Document doc = indexManager.getIndexSearcher().doc(scoreDoc.doc);
                final Map<String, String> fields = new HashMap<>();
                for (final IndexableField field: doc.getFields()) {
                    if (StringUtils.isNotBlank(field.stringValue())) {
                        fields.put(field.name(), field.stringValue());
                    }
                }
                resultSet.add(fields);
            }
            searchResult.addResultSet(indexManager.getIndexType().name().toLowerCase(), resultSet);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse search string", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.CORE_INDEXING_SERVICES)
                    .content("Failed to parse search string. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
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
            LOGGER.error("An I/O Exception occurred while searching Lucene index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.CORE_INDEXING_SERVICES)
                    .content("An I/O Exception occurred while searching Lucene index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }

        indexManager.close();
        return searchResult;
    }

    public SearchResult searchProjectIndex(final String queryString, final int limit) {
        return searchIndex(ProjectIndexer.getInstance(), queryString, limit);
    }

    public SearchResult searchComponentIndex(final String queryString, final int limit) {
        return searchIndex(ComponentIndexer.getInstance(), queryString, limit);
    }

    public SearchResult searchServiceComponentIndex(final String queryString, final int limit) {
        return searchIndex(ServiceComponentIndexer.getInstance(), queryString, limit);
    }

    public SearchResult searchLicenseIndex(final String queryString, final int limit) {
        return searchIndex(LicenseIndexer.getInstance(), queryString, limit);
    }

    public SearchResult searchVulnerabilityIndex(final String queryString, final int limit) {
        return searchIndex(VulnerabilityIndexer.getInstance(), queryString, limit);
    }

    /**
     * Escapes special characters used in Lucene query syntax.
     * + - && || ! ( ) { } [ ] ^ " ~ * ? : \ /
     *
     * @param input the text to escape
     * @return escaped text
     */
    private static String escape(final String input) {
        if(input == null) {
            return null;
        }
        char[] specialChars = {'+', '-', '!', '(', ')', '{', '}', '[', ']', '^', '"', '~', '*', '?', ':', '\\', '/'};
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            final char c = input.charAt(i);
            if (contains(specialChars, c)) {
                sb.append("\\" + c);
            } else {
                sb.append(String.valueOf(c));
            }
        }
        return sb.toString();
    }

    private static boolean contains(char[] chars, char queryChar) {
        for (char c : chars) {
            if (c == queryChar) {
                return true;
            }
        }
        return false;
    }
}
