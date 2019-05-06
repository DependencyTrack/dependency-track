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
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

/**
 * Defines a custom Dependency request object used when adding or removing a component as a dependency to/from a project.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class DependencyRequest {

    @NotNull
    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The project must be a valid 36 character UUID")
    private final String projectUuid;
    private String[] componentUuids;
    private final String notes;

    @JsonCreator
    public DependencyRequest(@JsonProperty(value = "projectUuid", required = true) String projectUuid,
                             @JsonProperty(value = "componentUuids", required = true) String[] componentUuids,
                             @JsonProperty(value = "notes") String notes) {
        this.projectUuid = projectUuid;
        if (componentUuids != null) {
            this.componentUuids = componentUuids.clone();
        }
        this.notes = notes;
    }

    public String getProjectUuid() {
        return projectUuid;
    }

    public String[] getComponentUuids() {
        return componentUuids != null ? componentUuids.clone() : null;
    }

    public String getNotes() {
        return notes;
    }

}
