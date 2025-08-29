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
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

@RunWith(JUnitParamsRunner.class)
public class GitHubMetaAnalyzerTest {

    private static final String COMMIT_LATEST_VERSION_TYPE_PATTERN = "^[a-f0-9]{7,40}$";
    private static final String RELEASE_LATEST_VERSION_TYPE_PATTERN = "^v.*$";

    @Test
    @Parameters(method = "testAnalyzerData")
    public void testAnalyzerInvalidTag(String purl, String latestVersionPattern, Boolean versionExists) throws Exception {
        final var component = new Component();
        component.setPurl(new PackageURL(purl));

        final var analyzer = new GithubMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.GITHUB, analyzer.supportedRepositoryType());

        MetaModel metaModel = analyzer.analyze(component);

        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertTrue(metaModel.getLatestVersion().matches(latestVersionPattern));
        if (versionExists) {
            Assert.assertNotNull(metaModel.getPublishedTimestamp());
        } else {
            Assert.assertNull(metaModel.getPublishedTimestamp());
        }
    }


    static Object[] testAnalyzerData() {
        return new Object[]{
                new Object[]{"pkg:github/CycloneDX/cdxgen@v9.8.9", RELEASE_LATEST_VERSION_TYPE_PATTERN, TRUE},
                new Object[]{"pkg:github/CycloneDX/cdxgen@4359dee1b7bd29ee25bc78e358a1254a0277ee96", COMMIT_LATEST_VERSION_TYPE_PATTERN, TRUE},
                new Object[]{"pkg:github/CycloneDX/cdxgen@4359dee", COMMIT_LATEST_VERSION_TYPE_PATTERN, TRUE},
                new Object[]{"pkg:github/CycloneDX/cdxgen", RELEASE_LATEST_VERSION_TYPE_PATTERN, FALSE},
                new Object[]{"pkg:github/CycloneDX/cdxgen@0000000", COMMIT_LATEST_VERSION_TYPE_PATTERN, FALSE},
                new Object[]{"pkg:github/CycloneDX/cdxgen@invalid-release", RELEASE_LATEST_VERSION_TYPE_PATTERN, FALSE},
                new Object[]{"pkg:github/google/gtm-session-fetcher@3.1.0", RELEASE_LATEST_VERSION_TYPE_PATTERN, FALSE},
                new Object[]{"pkg:github/boostorg/boost@1.88.0.beta1", "boost-.*", FALSE}
        };
    }
}
