/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
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
