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
package org.dependencytrack.pkgmetadata.resolution.pypi;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;

record PypiPackageDocument(
        @Nullable Info info,
        @Nullable Map<String, List<ReleaseFile>> releases) {

    record Info(@Nullable String version) {
    }

    record ReleaseFile(@Nullable String filename,
                       @JsonProperty("upload_time_iso_8601") @Nullable String uploadTime,
                       @Nullable Digests digests) {
    }

    record Digests(@Nullable String md5, @Nullable String sha256) {
    }

}
