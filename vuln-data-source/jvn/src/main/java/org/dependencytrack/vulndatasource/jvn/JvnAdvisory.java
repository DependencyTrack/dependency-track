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
package org.dependencytrack.vulndatasource.jvn;

import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.List;

/**
 * A parsed JVN advisory, as returned by the MyJVN {@code getVulnDetailInfo} API.
 *
 * @since 5.1.0
 */
record JvnAdvisory(
        String jvnDbId,
        @Nullable String title,
        @Nullable String overview,
        @Nullable String detail,
        @Nullable String recommendation,
        List<String> cveIds,
        List<Integer> cweIds,
        List<Cvss> cvssList,
        List<AffectedProduct> affected,
        List<String> referenceUrls,
        @Nullable Instant datePublic,
        @Nullable Instant dateLastUpdated) {

    /** An affected product: a single (product-level) CPE plus its Japanese version expressions. */
    record AffectedProduct(
            @Nullable String vendor,
            @Nullable String productName,
            String cpe22,
            List<String> versionTexts) {
    }

    /** A CVSS rating attached to the advisory. */
    record Cvss(
            @Nullable String version,
            @Nullable String severity,
            @Nullable Double baseScore,
            @Nullable String vector) {
    }
}
