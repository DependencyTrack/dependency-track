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
package org.dependencytrack.pkgmetadata.resolution.cache;

import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CacheKeysTest {

    @Test
    void shouldBuildWithSingleSegment() {
        assertThat(CacheKeys.build("foo")).isEqualTo("foo");
    }

    @Test
    void shouldBuildWithMultipleSegments() {
        assertThat(CacheKeys.build("a", "b", "c")).isEqualTo("a:b:c");
    }

    @Test
    void shouldBuildWithRepositoryWithoutCredentials() {
        final var repo = new PackageRepository("test", "https://repo.example.com", null, null);
        assertThat(CacheKeys.build(repo, "pkg")).isEqualTo("https://repo.example.com:pkg");
    }

    @Test
    void shouldBuildWithRepositoryWithCredentials() {
        final var repo = new PackageRepository("test", "https://repo.example.com", "user", "pass");
        final String key = CacheKeys.build(repo, "pkg");

        assertThat(key).isEqualTo("https://repo.example.com:ef4c914c591698b2:pkg");
    }

    @Test
    void shouldProduceDeterministicKeys() {
        final var repo = new PackageRepository("test", "https://repo.example.com", "user", "pass");
        assertThat(CacheKeys.build(repo, "pkg")).isEqualTo(CacheKeys.build(repo, "pkg"));
    }

    @Test
    void shouldProduceDifferentKeysForDifferentCredentials() {
        final var repo1 = new PackageRepository("test", "https://repo.example.com", "user", "pass1");
        final var repo2 = new PackageRepository("test", "https://repo.example.com", "user", "pass2");
        assertThat(CacheKeys.build(repo1, "pkg")).isNotEqualTo(CacheKeys.build(repo2, "pkg"));
    }

    @Test
    void shouldIncludeHashWhenOnlyUsernameIsSet() {
        final var repo = new PackageRepository("test", "https://repo.example.com", "user", null);
        final String key = CacheKeys.build(repo, "pkg");

        assertThat(key).isEqualTo("https://repo.example.com:0a478cd081990729:pkg");
    }

    @Test
    void shouldIncludeHashWhenOnlyPasswordIsSet() {
        final var repo = new PackageRepository("test", "https://repo.example.com", null, "token");
        final String key = CacheKeys.build(repo, "pkg");

        assertThat(key).isEqualTo("https://repo.example.com:510148ea0a912c70:pkg");
    }

    @Test
    void shouldBuildWithRepositoryAndMultipleSegments() {
        final var repo = new PackageRepository("test", "https://repo.example.com", null, null);
        assertThat(CacheKeys.build(repo, "ns", "name"))
                .isEqualTo("https://repo.example.com:ns:name");
    }

}
