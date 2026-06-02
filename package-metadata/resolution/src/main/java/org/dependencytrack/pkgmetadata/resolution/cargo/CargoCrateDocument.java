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
package org.dependencytrack.pkgmetadata.resolution.cargo;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

import java.util.List;

record CargoCrateDocument(
        @JsonProperty("crate") Crate crate,
        List<Version> versions) {

    record Crate(
            @JsonProperty("newest_version") @Nullable String newestVersion,
            @JsonProperty("max_stable_version") @Nullable String maxStableVersion) {
    }

    record Version(
            @Nullable String num,
            @JsonProperty("created_at") @Nullable String createdAt,
            @Nullable String checksum) {
    }

}
