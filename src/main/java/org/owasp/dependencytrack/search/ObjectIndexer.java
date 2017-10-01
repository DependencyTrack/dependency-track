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

}
