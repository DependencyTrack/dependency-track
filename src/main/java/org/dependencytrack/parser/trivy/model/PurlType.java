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
package org.dependencytrack.parser.trivy.model;

public enum PurlType {
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

    private final String appType;

    PurlType(final String appType) {
        this.appType = appType;
    }

    public String getAppType() {
        return appType;
    }

    public static class Constants {
        public static final String ALPM = "alpm";
        public static final String APK = "apk";
        public static final String BITBUCKET = "bitbucket";
        public static final String BITNAMI = "bitnami";
        public static final String CARGO = "cargo";
        public static final String COCOAPODS = "cocoapods";
        public static final String COMPOSER = "composer";
        public static final String CONAN = "conan";
        public static final String CONDA = "conda";
        public static final String CRAN = "cran";
        public static final String DEBIAN = "deb";
        public static final String DOCKER = "docker";
        public static final String GEM = "gem";
        public static final String GENERIC = "generic";
        public static final String GITHUB = "github";
        public static final String GOLANG = "golang";
        public static final String HACKAGE = "hackage";
        public static final String HEX = "hex";
        public static final String HUGGINGFACE = "huggingface";
        public static final String MAVEN = "maven";
        public static final String MLFLOW = "mlflow";
        public static final String NPM = "npm";
        public static final String NUGET = "nuget";
        public static final String OCI = "oci";
        public static final String PUB = "pub";
        public static final String PYPI = "pypi";
        public static final String QPKG = "qpkg";
        public static final String RPM = "rpm";
        public static final String SWID = "swid";
        public static final String SWIFT = "swift";
        public static final String UNKNOWN = "unknown";
        public static final String PACKAGES = "packages";
    }

    public static String getApp(String purlType) {
        if (purlType == null) {
            return PurlType.UNKNOWN.getAppType();
        }

        PurlType type;
        switch (purlType) {
            case PurlType.Constants.BITNAMI:
            type = PurlType.BITNAMI;
            break;
        case PurlType.Constants.CARGO:
            type = PurlType.CARGO;
            break;
        case PurlType.Constants.COCOAPODS:
            type = PurlType.COCOAPODS;
            break;
        case PurlType.Constants.COMPOSER:
            type = PurlType.COMPOSER;
            break;
        case PurlType.Constants.CONAN:
            type = PurlType.CONAN;
            break;
        case PurlType.Constants.CONDA:
            type = PurlType.CONDA;
            break;
        case PurlType.Constants.GEM:
            type = PurlType.GEM;
            break;
        case PurlType.Constants.GOLANG:
            type = PurlType.GOLANG;
            break;
        case PurlType.Constants.HEX:
            type = PurlType.HEX;
            break;
        case PurlType.Constants.MAVEN:
            type = PurlType.MAVEN;
            break;
        case PurlType.Constants.NPM:
            type = PurlType.NPM;
            break;
        case PurlType.Constants.NUGET:
            type = PurlType.NUGET;
            break;
        case PurlType.Constants.PUB:
            type = PurlType.PUB;
            break;
        case PurlType.Constants.PYPI:
            type = PurlType.PYPI;
            break;
        case PurlType.Constants.SWIFT:
            type = PurlType.SWIFT;
            break;
        case PurlType.Constants.ALPM:
            type = PurlType.ALPM;
            break;
        case PurlType.Constants.APK:
            type = PurlType.APK;
            break;
        case PurlType.Constants.BITBUCKET:
            type = PurlType.BITBUCKET;
            break;
        case PurlType.Constants.CRAN:
            type = PurlType.CRAN;
            break;
        case PurlType.Constants.DEBIAN:
            type = PurlType.DEBIAN;
            break;
        case PurlType.Constants.DOCKER:
            type = PurlType.DOCKER;
            break;
        case PurlType.Constants.GENERIC:
            type = PurlType.GENERIC;
            break;
        case PurlType.Constants.GITHUB:
            type = PurlType.GITHUB;
            break;
        case PurlType.Constants.HACKAGE:
            type = PurlType.HACKAGE;
            break;
        case PurlType.Constants.HUGGINGFACE:
            type = PurlType.HUGGINGFACE;
            break;
        case PurlType.Constants.MLFLOW:
            type = PurlType.MLFLOW;
            break;
        case PurlType.Constants.OCI:
            type = PurlType.OCI;
            break;
        case PurlType.Constants.QPKG:
            type = PurlType.QPKG;
            break;
        case PurlType.Constants.RPM:
            type = PurlType.RPM;
            break;
        case PurlType.Constants.SWID:
            type = PurlType.SWID;
            break;
        default:
            type = PurlType.UNKNOWN;
            break;
        }

        return type.getAppType();
    }
}
