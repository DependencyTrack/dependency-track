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

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.IndexableField;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopDocs;
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

    public SearchResult searchIndices(String queryString, int limit) {
        final SearchResult searchResult = new SearchResult();
        final IndexManager[] indexManagers = {
                ProjectIndexer.getInstance(),
                ComponentIndexer.getInstance(),
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

    public SearchResult searchIndex(IndexManager indexManager, String queryString, int limit) {
        final SearchResult searchResult = new SearchResult();
        final List<Map<String, String>> resultSet = new ArrayList<>();
        try {
            final StringBuilder sb = new StringBuilder();
            sb.append(queryString);
            sb.append("^100");
            sb.append(" OR ");
            sb.append(queryString);
            sb.append("*");
            sb.append("^5");
            sb.append(" OR ");
            sb.append("*");
            sb.append(queryString);
            sb.append("*");

            final Query query = indexManager.getQueryParser().parse(sb.toString());
            final TopDocs results = indexManager.getIndexSearcher().search(query, limit);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Searching for: " + queryString + " - Total Hits: " + results.totalHits);
            }

            for (ScoreDoc scoreDoc: results.scoreDocs) {
                final Document doc = indexManager.getIndexSearcher().doc(scoreDoc.doc);
                final Map<String, String> fields = new HashMap<>();
                for (IndexableField field: doc.getFields()) {
                    if (StringUtils.isNotBlank(field.stringValue())) {
                        fields.put(field.name(), field.stringValue());
                    }
                }
                resultSet.add(fields);
            }
            searchResult.addResultSet(indexManager.getIndexType().name().toLowerCase(), resultSet);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse search string.");
        } catch (CorruptIndexException e) {
            LOGGER.error("Corrupted Lucene Index Detected:\n" + e.getMessage());
        } catch (IOException e) {
            LOGGER.error("IO Exception searching Lucene Index:\n" + e.getMessage());
        }

        indexManager.close();
        return searchResult;
    }

}
