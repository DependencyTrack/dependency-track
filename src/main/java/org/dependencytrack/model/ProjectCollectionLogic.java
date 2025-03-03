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
package org.dependencytrack.model;

/**
 * Defines various types of logics to be applied to collection projects.
 * Collection projects don't contain own components, instead collect their metrics and
 * data from their children. The logic to apply when calculating this data is defined
 * by this type.
 *
 * @author Ralf King
 * @since 4.13.0
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
     * Aggregate all direct children marked with isLatest flag.
     */
    AGGREGATE_LATEST_VERSION_CHILDREN
}
