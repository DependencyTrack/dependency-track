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
package org.dependencytrack.parser.npm.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Defines the top-level JSON node containing results and counts.
 *
 * @author Steve Springett
 * @since 3.2.1
 */
public class AdvisoryResults {

    private String next;
    private String previous;
    private int total;
    private final List<Advisory> advisoryList = new ArrayList<>();

    public String getNext() {
        return next;
    }

    public void setNext(String next) {
        this.next = next;
    }

    public String getPrevious() {
        return previous;
    }

    public void setPrevious(String previous) {
        this.previous = previous;
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
