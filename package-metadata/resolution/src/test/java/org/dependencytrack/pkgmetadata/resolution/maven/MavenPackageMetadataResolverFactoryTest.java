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
package org.dependencytrack.pkgmetadata.resolution.maven;

import com.github.packageurl.PackageURL;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class MavenPackageMetadataResolverFactoryTest extends AbstractExtensionFactoryTest<PackageMetadataResolver, MavenPackageMetadataResolverFactory> {

    protected MavenPackageMetadataResolverFactoryTest() {
        super(MavenPackageMetadataResolverFactory.class);
    }

    @ParameterizedTest
    @CsvSource(nullValues = "", value = {
            "pkg:maven/com.example/foo@1.0, pkg:maven/com.example/foo@1.0?type=jar",
            "pkg:maven/com.example/foo@1.0?type=pom, pkg:maven/com.example/foo@1.0?type=pom",
            "pkg:maven/com.example/foo@1.0?classifier=sources&type=jar, pkg:maven/com.example/foo@1.0?classifier=sources&type=jar",
            "pkg:maven/com.example/foo@1.0?type=jar&unrelated=value#sub/path, pkg:maven/com.example/foo@1.0?type=jar",
            "pkg:npm/foo@1.0, ",
            "pkg:maven/com.example/foo, ",
    })
    void shouldNormalize(String input, String expected) throws Exception {
        assertThat(factory.normalize(new PackageURL(input)))
                .isEqualTo(expected != null ? new PackageURL(expected) : null);
    }

    @Test
    void shouldRequireRepository() {
        assertThat(factory.requiresRepository()).isTrue();
    }

}
