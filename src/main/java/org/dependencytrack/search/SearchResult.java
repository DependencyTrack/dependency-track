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

    private final Map<String, List<Map<String, String>>> results = Collections.synchronizedMap(new HashMap<>());

    public  Map<String, List<Map<String, String>>> getResults() {
        return results;
    }

    public void addResultSet(final String key, final List<Map<String, String>> resultSet) {
        results.put(key, resultSet);
    }

}
