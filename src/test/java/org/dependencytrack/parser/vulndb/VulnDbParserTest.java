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
package org.dependencytrack.parser.vulndb;

import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.vulndb.model.Results;
import org.junit.Test;

import java.io.File;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class VulnDbParserTest {

    @Test
    public void test() throws Exception {
        String filePath = "src/test/resources/unit/vulndb.jsons/vulnerabilities_0.json";
        File file = new File(filePath);
        final VulnDbParser parser = new VulnDbParser();
        final Results<Vulnerability> results = parser.parse(file, org.dependencytrack.parser.vulndb.model.Vulnerability.class);
        final List<Vulnerability> vulns = results.getResults();
        assertThat(vulns).hasSize(3);
    }

}