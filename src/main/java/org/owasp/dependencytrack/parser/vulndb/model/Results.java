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
package org.owasp.dependencytrack.parser.vulndb.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Defines a top-level Results object containing a list of
 * possible results and count/page data.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class Results {

    private int page;
    private int total;
    private List<Object> results = new ArrayList<>();

    public int getPage() {
        return page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public List<Object> getResults() {
        return results;
    }

    @SuppressWarnings("unchecked")
    public void setResults(List objects) {
        this.results = objects;
    }

    public void add(Object object) {
        results.add(object);
    }
}
