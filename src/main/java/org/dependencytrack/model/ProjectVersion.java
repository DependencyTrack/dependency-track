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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.io.Serializable;

/**
 * Value object holding UUID and version for a project
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProjectVersion implements Serializable {

    private static final long serialVersionUID = 1L;

    private String uuid;

    private String version;

    public ProjectVersion(String uuid, String version) {
        this.uuid = uuid;
        this.version = version;

    }
    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getUuid() {
        return uuid;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getVersion() {
        return version;
    }
}
