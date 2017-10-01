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
package org.owasp.dependencytrack.parser.nsp.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Defines the top-level JSON node containing results and counts.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class AdvisoryResults {

    private int offset;
    private int count;
    private int total;
    private final List<Advisory> advisoryList = new ArrayList<>();

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public List<Advisory> getAdvisories() {
        return advisoryList;
    }

    public void add(Advisory advisory) {
        advisoryList.add(advisory);
    }

}
