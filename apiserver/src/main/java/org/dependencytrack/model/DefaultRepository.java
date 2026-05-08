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
 * @since 5.0.0
 */
public enum DefaultRepository {

    CPAN_PUBLIC_REGISTRY(RepositoryType.CPAN, "cpan-public-registry", "https://fastapi.metacpan.org/v1/", 1),
    GEM_RUBYGEMS(RepositoryType.GEM, "rubygems.org", "https://rubygems.org/", 1),
    HEX_HEX_PM(RepositoryType.HEX, "hex.pm", "https://hex.pm/", 1),
    MAVEN_CENTRAL(RepositoryType.MAVEN, "central", "https://repo1.maven.org/maven2/", 1),
    MAVEN_ATLASSIAN_PUBLIC(RepositoryType.MAVEN, "atlassian-public", "https://packages.atlassian.com/content/repositories/atlassian-public/", 2),
    MAVEN_JBOSS_RELEASES(RepositoryType.MAVEN, "jboss-releases", "https://repository.jboss.org/nexus/content/repositories/releases/", 3),
    MAVEN_CLOJARS(RepositoryType.MAVEN, "clojars", "https://repo.clojars.org/", 4),
    MAVEN_GOOGLE_ANDROID(RepositoryType.MAVEN, "google-android", "https://maven.google.com/", 5),
    NPM_PUBLIC_REGISTRY(RepositoryType.NPM, "npm-public-registry", "https://registry.npmjs.org/", 1),
    PYPI_PYPI_ORG(RepositoryType.PYPI, "pypi.org", "https://pypi.org/", 1),
    NUGET_GALLERY(RepositoryType.NUGET, "nuget-gallery", "https://api.nuget.org/", 1),
    COMPOSER_PACKAGIST(RepositoryType.COMPOSER, "packagist", "https://repo.packagist.org/", 1),
    CARGO_CRATES_IO(RepositoryType.CARGO, "crates.io", "https://crates.io", 1),
    GO_PROXY_GOLANG_ORG(RepositoryType.GO_MODULES, "proxy.golang.org", "https://proxy.golang.org", 1),
    GITHUB(RepositoryType.GITHUB, "github", "https://github.com", 1),
    HACKAGE(RepositoryType.HACKAGE, "hackage.haskell", "https://hackage.haskell.org/", 1),
    NIXPKGS_NIXOS_ORG(RepositoryType.NIXPKGS, "nixos.org", "https://channels.nixos.org/nixpkgs-unstable/packages.json.br", 1);

    private final RepositoryType type;
    private final String identifier;
    private final String url;
    private final int resolutionOrder;

    DefaultRepository(final RepositoryType type, final String identifier, final String url, final int resolutionOrder) {
        this.type = type;
        this.identifier = identifier;
        this.url = url;
        this.resolutionOrder = resolutionOrder;
    }

    public RepositoryType getType() {
        return type;
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getUrl() {
        return url;
    }

    public int getResolutionOrder() {
        return resolutionOrder;
    }

}
