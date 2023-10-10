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
package org.dependencytrack.persistence;

import alpine.model.Team;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Tag;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Builder for filters meant to be used with {@link javax.jdo.Query#setFilter} and the query's
 * parameters that can be passed to {@link alpine.persistence.AbstractAlpineQueryManager#execute}
 * <br>
 * Mutable and not threadsafe!
 */
class ProjectQueryFilterBuilder {

    private final Map<String, Object> params;
    private final List<String> filterCriteria;

    ProjectQueryFilterBuilder() {
        this.params = new HashMap<>();
        this.filterCriteria = new ArrayList<>();
    }

    ProjectQueryFilterBuilder excludeInactive(boolean excludeInactive) {
        if (excludeInactive) {
            filterCriteria.add("(active == true || active == null)");
        }
        return this;
    }

    ProjectQueryFilterBuilder withTeam(Team team) {
        params.put("team", team);
        filterCriteria.add("(accessTeams.contains(:team))");
        return this;
    }

    ProjectQueryFilterBuilder withName(String name) {
        params.put("name", name);
        filterCriteria.add("(name == :name)");
        return this;
    }

    ProjectQueryFilterBuilder withVersion(String version) {
        params.put("version", version);
        filterCriteria.add("(version == :version)");
        return this;
    }

    ProjectQueryFilterBuilder withTag(Tag tag) {
        params.put("tag", tag);
        filterCriteria.add("(tags.contains(:tag))");
        return this;
    }

    ProjectQueryFilterBuilder withClassifier(Classifier classifier) {
        params.put("classifier", classifier);
        filterCriteria.add("(classifier == :classifier)");
        return this;
    }

    ProjectQueryFilterBuilder withFuzzyName(String name) {
        params.put("name", name);

        filterCriteria.add("(name.toLowerCase().matches(:name))");
        return this;
    }

    ProjectQueryFilterBuilder withFuzzyNameOrExactTag(String name, Tag tag) {
        params.put("name", name);
        params.put("tag", tag);

        filterCriteria.add("(name.toLowerCase().matches(:name) || tags.contains(:tag))");
        return this;
    }

    ProjectQueryFilterBuilder excludeChildProjects() {
        filterCriteria.add("parent == null");
        return this;
    }

    ProjectQueryFilterBuilder withParent(UUID uuid){
        params.put("parentUuid", uuid);

        filterCriteria.add("parent.uuid == :parentUuid");
        return this;
    }

    String buildFilter() {
        return String.join(" && ", this.filterCriteria);
    }

    Map<String, Object> getParams() {
        return params;
    }
}
