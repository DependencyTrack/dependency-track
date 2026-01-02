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
package org.dependencytrack.tasks.repositories;

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

// TODO this depends on an external API and will fail if that API doesn't respond fast enough; this especially
//      happens rather fast when executing tests locally repeatedly
@Timeout(value = 5, unit = TimeUnit.SECONDS)
class GitHubMetaAnalyzerTest {

    private static final String COMMIT_LATEST_VERSION_TYPE_PATTERN = "^[a-f0-9]{7,40}$";
    private static final String RELEASE_LATEST_VERSION_TYPE_PATTERN = "^v.*$";

    @ParameterizedTest
    @MethodSource("testAnalyzerData")
    void testAnalyzerInvalidTag(String purl, String latestVersionPattern, Boolean versionExists) throws Exception {
        final var component = new Component();
        component.setPurl(new PackageURL(purl));

        final var analyzer = new GithubMetaAnalyzer();
        Assertions.assertTrue(analyzer.isApplicable(component));
        Assertions.assertEquals(RepositoryType.GITHUB, analyzer.supportedRepositoryType());

        MetaModel metaModel = analyzer.analyze(component);

        Assertions.assertNotNull(metaModel.getLatestVersion());
        Assertions.assertTrue(metaModel.getLatestVersion().matches(latestVersionPattern));
        if (versionExists) {
            Assertions.assertNotNull(metaModel.getPublishedTimestamp());
        } else {
            Assertions.assertNull(metaModel.getPublishedTimestamp());
        }
    }


    static Stream<Arguments> testAnalyzerData() {
        return Stream.of(
                Arguments.of("pkg:github/CycloneDX/cdxgen@v9.8.9", RELEASE_LATEST_VERSION_TYPE_PATTERN, TRUE),
                Arguments.of("pkg:github/CycloneDX/cdxgen@4359dee1b7bd29ee25bc78e358a1254a0277ee96", COMMIT_LATEST_VERSION_TYPE_PATTERN, TRUE),
                Arguments.of("pkg:github/CycloneDX/cdxgen@4359dee", COMMIT_LATEST_VERSION_TYPE_PATTERN, TRUE),
                Arguments.of("pkg:github/CycloneDX/cdxgen", RELEASE_LATEST_VERSION_TYPE_PATTERN, FALSE),
                Arguments.of("pkg:github/CycloneDX/cdxgen@0000000", COMMIT_LATEST_VERSION_TYPE_PATTERN, FALSE),
                Arguments.of("pkg:github/CycloneDX/cdxgen@invalid-release", RELEASE_LATEST_VERSION_TYPE_PATTERN, FALSE),
                Arguments.of("pkg:github/google/gtm-session-fetcher@3.1.0", RELEASE_LATEST_VERSION_TYPE_PATTERN, FALSE),
                Arguments.of("pkg:github/boostorg/boost@1.88.0.beta1", "boost-.*", FALSE)
        );
    }
}
