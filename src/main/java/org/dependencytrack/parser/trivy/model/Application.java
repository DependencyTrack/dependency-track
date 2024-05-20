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

import java.util.ArrayList;
import java.util.List;

public class Application {

    private String type;
    private List<Package> packages;

    /**
     * NB: GSON doesn't support serialization of getters, it can only deal with fields.
     * Need to have libraries as redundant field to packages, with Jackson we could just
     * use a computed getter with {@link com.fasterxml.jackson.annotation.JsonGetter}.
     * Migrate this to Jackson eventually.
     *
     * @see <a href="https://github.com/DependencyTrack/dependency-track/issues/3737">GitHub issue</a>
     * @deprecated Kept for compatibility with Trivy <= 0.51.1
     */
    @Deprecated(forRemoval = true)
    private List<Package> libraries;

    public Application(final String type) {
        this.type = type;
        this.packages = new ArrayList<>();
        this.libraries = new ArrayList<>();
    }

    public String getType() {
        return type;
    }

    public void setType(String value) {
        this.type = value;
    }

    public List<Package> getPackages() {
        return packages;
    }

    public void setPackages(List<Package> value) {
        this.packages = value;
        this.libraries = value;
    }

    public void addPackage(Package value) {
        this.packages.add(value);
        this.libraries.add(value);
    }

}