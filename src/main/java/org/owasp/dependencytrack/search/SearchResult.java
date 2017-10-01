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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Wrapper class for returning search results.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class SearchResult {

    private Map<String, List<Map<String, String>>> results = Collections.synchronizedMap(new HashMap<>());

    public  Map<String, List<Map<String, String>>> getResults() {
        return results;
    }

    public void addResultSet(String key, List<Map<String, String>> resultSet) {
        results.put(key, resultSet);
    }

}
