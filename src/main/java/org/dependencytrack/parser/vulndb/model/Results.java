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
package org.dependencytrack.parser.vulndb.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Defines a top-level Results object containing a list of
 * possible results and count/page data.
 *
 * @author Steve Springett
 */
public class Results<T> {
    private int page;
    private int total;
    private List<T> results = new ArrayList();
    private String rawResults;
    private String errorCondition;

    public Results() {
    }

    public int getPage() {
        return this.page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public int getTotal() {
        return this.total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public List<T> getResults() {
        return this.results;
    }

    public void setResults(List objects) {
        this.results = objects;
    }

    public void add(T object) {
        this.results.add(object);
    }

    public String getRawResults() {
        return this.rawResults;
    }

    public void setRawResults(String rawResults) {
        this.rawResults = rawResults;
    }

    public boolean isSuccessful() {
        return this.errorCondition == null;
    }

    public String getErrorCondition() {
        return this.errorCondition;
    }

    public void setErrorCondition(String errorCondition) {
        this.errorCondition = errorCondition;
    }
}
