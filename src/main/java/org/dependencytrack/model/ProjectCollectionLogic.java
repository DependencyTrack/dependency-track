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

/**
 * Defines various types of logics to be applied to collection projects.
 * Collection projects don't contain own components, instead collect their metrics and
 * data from their children. The logic to apply when calculating this data is defined
 * by this type.
 *
 * @author Ralf King
 * @since 4.11.0
 */
public enum ProjectCollectionLogic {
    /**
     * Project is not a collection project
     */
    NONE,
    /**
     * Aggregate data from all direct children. Respects collection logic of
     * direct children collections.
     */
    AGGREGATE_DIRECT_CHILDREN,
    /**
     * Aggregate all direct children which have a specific tag
     */
    AGGREGATE_DIRECT_CHILDREN_WITH_TAG,
    /**
     * Find the child with the highest SemVer version and show only that child's data.
     * Ignores children not using SemVer versions.
     */
    HIGHEST_SEMVER_CHILD
}
