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
package org.dependencytrack.model;

import com.github.packageurl.PackageURL;

/**
 * Defines repository resources.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public enum RepositoryType {

    MAVEN,
    NPM,
    GEM,
    UNSUPPORTED;

    /**
     * Returns a RepositoryType for the specified PackageURL.
     * @param packageURL a package URL
     * @return a RepositoryType
     */
    public static RepositoryType resolve(PackageURL packageURL) {
        final String type = packageURL.getType();
        if (PackageURL.StandardTypes.MAVEN.equals(type)) {
            return MAVEN;
        } else if (PackageURL.StandardTypes.NPM.equals(type)) {
            return NPM;
        } else if (PackageURL.StandardTypes.GEM.equals(type)) {
            return GEM;
        }
        return UNSUPPORTED;
    }

}
