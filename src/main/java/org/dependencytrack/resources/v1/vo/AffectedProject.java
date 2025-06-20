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
package org.dependencytrack.resources.v1.vo;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Describes a project that is affected by a specific vulnerability, including a list of UUIDs of the components
 * affected by the vulnerability within this project.
 *
 * @author Ralf King
 * @since 4.11.0
 */
public class AffectedProject {
    private final UUID uuid;

    private final boolean dependencyGraphAvailable;

    private final String name;

    private final String version;

    private final boolean active;

    private final List<UUID> affectedComponentUuids;

    public AffectedProject(UUID uuid, boolean dependencyGraphAvailable, String name, String version, boolean active, List<UUID> affectedComponentUuids) {
        this.uuid = uuid;
        this.dependencyGraphAvailable = dependencyGraphAvailable;
        this.name = name;
        this.version = version;
        this.active = active;
        this.affectedComponentUuids = affectedComponentUuids == null ? new ArrayList<>() : affectedComponentUuids;
    }

    public UUID getUuid() {
        return uuid;
    }

    public boolean isDependencyGraphAvailable() {
        return dependencyGraphAvailable;
    }
    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public boolean getActive() {
        return active;
    }

    public List<UUID> getAffectedComponentUuids() {
        return affectedComponentUuids;
    }
}
