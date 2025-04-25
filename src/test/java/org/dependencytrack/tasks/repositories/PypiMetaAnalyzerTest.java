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

class PypiMetaAnalyzerTest {

    @Test
    void testAnalyzer() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:pypi/Flask@1.0.0"));

        PypiMetaAnalyzer analyzer = new PypiMetaAnalyzer();
        Assertions.assertTrue(analyzer.isApplicable(component));
        Assertions.assertEquals(RepositoryType.PYPI, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assertions.assertNotNull(metaModel.getLatestVersion());
        Assertions.assertNotNull(metaModel.getPublishedTimestamp());
    }
}
