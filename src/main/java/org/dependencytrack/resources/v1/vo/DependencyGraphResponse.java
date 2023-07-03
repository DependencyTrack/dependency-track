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

import java.io.Serializable;
import java.util.UUID;

/**
 * Response-Object that represent light component or service for rendering DependencyGraph
 *
 * @author Nathan Mittelette <mittelette.nathan@gmail.com>
 * @since 4.9.0
 */
public record DependencyGraphResponse(UUID uuid, String name, String version, String purl, String directDependencies, String latestVersion) implements Serializable {

    public DependencyGraphResponse(DependencyGraphResponse source, String latestVersion) {
        this(source.uuid(), source.name(), source.version(), source.purl(), source.directDependencies(), latestVersion);
    }

}
