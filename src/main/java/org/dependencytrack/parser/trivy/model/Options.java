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

import com.google.gson.annotations.SerializedName;

public class Options {

    /**
     * NB: GSON doesn't support serialization of getters, it can only deal with fields.
     * Need to have libraries as redundant field to packages, with Jackson we could just
     * use a computed getter with {@link com.fasterxml.jackson.annotation.JsonGetter}.
     * Migrate this to Jackson eventually.
     *
     * @see <a href="https://github.com/DependencyTrack/dependency-track/issues/3737">GitHub issue</a>
     * @deprecated Kept for compatibility with Trivy < 0.54.0
     */
    @Deprecated(forRemoval = true)
    @SerializedName("vuln_type")
    private String[] vulnType;

    @SerializedName("pkg_types")
    private String[] pkgTypes;

    private String[] scanners;

    public void setPkgTypes(String[] value) {
        this.pkgTypes = value;
        this.vulnType = value;
    }

    public void setScanners(String[] value) {
        this.scanners = value;
    }

}