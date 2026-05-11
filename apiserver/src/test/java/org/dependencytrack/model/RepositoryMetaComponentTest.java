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
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class RepositoryMetaComponentTest {

    @Test
    void shouldConvertFromPackageMetadata() throws Exception {
        final var purl = new PackageURL("pkg:maven/com.acme/acme-lib");
        final var resolvedAt = Instant.now();
        final var packageMetadata = new PackageMetadata(purl, "2.0.0", resolvedAt, resolvedAt, null, null);

        final var repoMetaComponent = RepositoryMetaComponent.of(packageMetadata);
        assertThat(repoMetaComponent.getRepositoryType()).isEqualTo(RepositoryType.MAVEN);
        assertThat(repoMetaComponent.getNamespace()).isEqualTo("com.acme");
        assertThat(repoMetaComponent.getName()).isEqualTo("acme-lib");
        assertThat(repoMetaComponent.getLatestVersion()).isEqualTo("2.0.0");
        assertThat(repoMetaComponent.getLastCheck()).isNotNull();
        assertThat(repoMetaComponent.getLatestVersionPublishedAt()).isNotNull();
    }

}
