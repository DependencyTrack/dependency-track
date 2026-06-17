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

import com.github.packageurl.PackageURL;

/**
 * Defines repository resources.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public enum RepositoryType {

    CPAN,
    MAVEN,
    NPM,
    GEM,
    PYPI,
    NUGET,
    HEX,
    COMPOSER,
    CARGO,
    GO_MODULES,
    CPAN,
    GITHUB,
    HACKAGE,
    NIXPKGS,
    UNSUPPORTED;

    /**
     * Returns a RepositoryType for the specified PackageURL.
     *
     * @param packageURL a package URL
     * @return a RepositoryType
     */
    public static RepositoryType resolve(PackageURL packageURL) {
        return ofPurlType(packageURL.getType());
    }

    public static RepositoryType ofPurlType(String purlType) {
        return switch (purlType) {
            case "cpan" -> CPAN;
            case "hackage" -> HACKAGE;
            case "nixpkgs" -> NIXPKGS;
            case PackageURL.StandardTypes.CARGO -> CARGO;
            case PackageURL.StandardTypes.COMPOSER -> COMPOSER;
            case PackageURL.StandardTypes.GEM -> GEM;
            case PackageURL.StandardTypes.GITHUB -> GITHUB;
            case PackageURL.StandardTypes.GOLANG -> GO_MODULES;
            case PackageURL.StandardTypes.HEX -> HEX;
            case PackageURL.StandardTypes.MAVEN -> MAVEN;
            case PackageURL.StandardTypes.NPM -> NPM;
            case PackageURL.StandardTypes.NUGET -> NUGET;
            case PackageURL.StandardTypes.PYPI -> PYPI;
            case null, default -> UNSUPPORTED;
        };
    }

}
