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

/**
 * Interface that defines Indexers.
 * @param <T> type of indexer
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public interface ObjectIndexer<T> {

    /**
     * Search fields supported by the index.
     * @return an array of Strings
     */
    String[] getSearchFields();

    /**
     * Add object to index.
     * @param object the object to add
     */
    void add(T object);

    /**
     * Remove object from index.
     * @param object the object to remove
     */
    void remove(T object);

    /**
     * Commits any changes to the index.
     */
    void commit();

    /**
     * Re-indexes all objects of the ObjectIndexer type.
     * @since 3.4.0
     */
    void reindex();

}
