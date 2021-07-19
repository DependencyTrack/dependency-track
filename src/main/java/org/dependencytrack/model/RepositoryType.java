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
    PYPI,
    NUGET,
    HEX,
    COMPOSER,
    CARGO,
    GO_MODULES,
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
        } else if (PackageURL.StandardTypes.PYPI.equals(type)) {
            return PYPI;
        } else if (PackageURL.StandardTypes.NUGET.equals(type)) {
            return NUGET;
        } else if (PackageURL.StandardTypes.HEX.equals(type)) {
            return HEX;
        } else if (PackageURL.StandardTypes.COMPOSER.equals(type)) {
            return COMPOSER;
        } else if (PackageURL.StandardTypes.CARGO.equals(type)) {
            return CARGO;
        } else if (PackageURL.StandardTypes.GOLANG.equals(type)) {
            return GO_MODULES;
        }
        return UNSUPPORTED;
    }

}
