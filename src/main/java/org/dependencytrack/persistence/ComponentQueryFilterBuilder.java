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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.persistence;

import org.dependencytrack.model.Classifier;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Builder for filters meant to be used with {@link javax.jdo.Query#setFilter} and the query's
 * parameters that can be passed to {@link alpine.persistence.AbstractAlpineQueryManager#execute}
 * <br>
 * Mutable and not threadsafe!
 */
class ComponentQueryFilterBuilder {

    private final Map<String, Object> params;
    private final List<String> filterCriteria;

    ComponentQueryFilterBuilder() {
        this.params = new HashMap<>();
        this.filterCriteria = new ArrayList<>();
    }

    ComponentQueryFilterBuilder withFuzzyName(String name) {
        params.put("name", name);
        filterCriteria.add("(name.toLowerCase().matches(:name))");
        return this;
    }
    
    ComponentQueryFilterBuilder withAuthor(string author) {
        params.put("author", author);
        filterCriteria.add("(author == :author)");
        return this;
    }

    ComponentQueryFilterBuilder withClassifier(Classifier classifier) {
        params.put("classifier", classifier);
        filterCriteria.add("(classifier == :classifier)");
        return this;
    }

    String buildFilter() {
        return String.join(" && ", this.filterCriteria);
    }

    Map<String, Object> getParams() {
        return params;
    }
}
