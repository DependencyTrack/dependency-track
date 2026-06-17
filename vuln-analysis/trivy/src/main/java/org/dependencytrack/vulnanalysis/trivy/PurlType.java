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
package org.dependencytrack.vulnanalysis.trivy;

import org.jspecify.annotations.Nullable;

import java.util.Map;

enum PurlType {

    // Library types (application scanners)
    BITNAMI("bitnami"),
    CARGO("cargo"),
    COCOAPODS("cocoapods"),
    COMPOSER("composer"),
    CONAN("conan"),
    CONDA("conda-pkg"),
    GEM("gemspec"),
    GOLANG("gobinary"),
    HEX("hex"),
    MAVEN("jar"),
    NPM("node-pkg"),
    NUGET("nuget"),
    PUB("pub"),
    PYPI("python-pkg"),
    SWIFT("swift"),

    // OS package types
    ALPM("packages"),
    APK("packages"),
    BITBUCKET("packages"),
    CRAN("packages"),
    DEBIAN("packages"),
    DOCKER("packages"),
    GENERIC("packages"),
    GITHUB("packages"),
    HACKAGE("packages"),
    HUGGINGFACE("packages"),
    MLFLOW("packages"),
    OCI("packages"),
    QPKG("packages"),
    RPM("packages"),
    SWID("packages"),

    UNKNOWN("unknown");

    static final String APP_TYPE_PACKAGES = "packages";
    static final String APP_TYPE_UNKNOWN = "unknown";

    private static final Map<String, PurlType> BY_PURL_TYPE = Map.ofEntries(
            Map.entry("bitnami", BITNAMI),
            Map.entry("cargo", CARGO),
            Map.entry("cocoapods", COCOAPODS),
            Map.entry("composer", COMPOSER),
            Map.entry("conan", CONAN),
            Map.entry("conda", CONDA),
            Map.entry("gem", GEM),
            Map.entry("golang", GOLANG),
            Map.entry("hex", HEX),
            Map.entry("maven", MAVEN),
            Map.entry("npm", NPM),
            Map.entry("nuget", NUGET),
            Map.entry("pub", PUB),
            Map.entry("pypi", PYPI),
            Map.entry("swift", SWIFT),
            Map.entry("alpm", ALPM),
            Map.entry("apk", APK),
            Map.entry("bitbucket", BITBUCKET),
            Map.entry("cran", CRAN),
            Map.entry("deb", DEBIAN),
            Map.entry("docker", DOCKER),
            Map.entry("generic", GENERIC),
            Map.entry("github", GITHUB),
            Map.entry("hackage", HACKAGE),
            Map.entry("huggingface", HUGGINGFACE),
            Map.entry("mlflow", MLFLOW),
            Map.entry("oci", OCI),
            Map.entry("qpkg", QPKG),
            Map.entry("rpm", RPM),
            Map.entry("swid", SWID)
    );

    private final String appType;

    PurlType(String appType) {
        this.appType = appType;
    }

    String appType() {
        return appType;
    }

    static String getAppType(@Nullable String purlType) {
        if (purlType == null) {
            return APP_TYPE_UNKNOWN;
        }
        final PurlType type = BY_PURL_TYPE.get(purlType);
        return type != null ? type.appType : APP_TYPE_UNKNOWN;
    }

}
