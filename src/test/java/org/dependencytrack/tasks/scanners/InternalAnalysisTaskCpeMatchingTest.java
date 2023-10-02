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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.scanners;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.InternalAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.nvd.ModelConverter;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED;

@RunWith(Parameterized.class)
public class InternalAnalysisTaskCpeMatchingTest extends PersistenceCapableTest {

    @Parameters(name = "{index} source={0}, target={2}, expectMatch={1}")
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                {"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*", MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:o:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:a:rodnev:product:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:a:vendor:tcudorp:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.1.1:*:*:*:*:*:*:*"},
                // ---
                // Regression tests
                // ---
                // #2988: "other" attribute of source is NA, "other" attribute of target is ANY -> SUBSET.
                {"cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:NA", MATCHES, "cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:*"},
                // #2988: "target_hw" of source if x64, "target_hw" of target is ANY -> SUBSET.
                {"cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:x86:*", MATCHES, "cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:*"},
                // #2988: "vendor" of source contains wildcard, "vendor" of target is ANY -> SUBSET.
                {"cpe:2.3:o:linu*:linux_kernel:5.15.37:*:*:*:*:*:*:*", MATCHES, "cpe:2.3:o:*:linux_kernel:5.15.37:*:*:*:*:*:*:*"},
                // #2580: "vendor" of source is "linux", "vendor" of target ANY -> SUBSET.
                {"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", MATCHES, "cpe:2.3:o:*:linux_kernel:4.19.139:*:*:*:*:*:*:*"},
                // #2994: "part" of source is "a", "part" of target is ANY -> SUBSET.
                {"cpe:2.3:a:busybox:busybox:1.34.1:*:*:*:*:*:*:*", MATCHES, "cpe:2.3:*:busybox:busybox:1.34.1:*:*:*:*:*:*:*"},
                // #2894: "vendor" and "product" with different casing -> EQUAL.
                // Note: CPEs with uppercase "part" are considered invalid by the cpe-parser library.
                {"cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:*", MATCHES, "cpe:2.3:o:LiNuX:LiNuX_kErNeL:5.15.37:*:*:*:*:*:*:*"},
                // #1832: "version" of source is NA, "version" of target is "2.4.54" -> DISJOINT.
                {"cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*", MATCHES, "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*"},
                // #1832: "version" of source is NA, "version" of target is ANY -> SUBSET.
                {"cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*", MATCHES, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
                // #2188: "update" of source is NA, "update" of target is ANY -> SUBSET.
                {"cpe:2.3:a:xiph:speex:1.2:-:*:*:*:*:*:*", MATCHES, "cpe:2.3:a:xiph:speex:1.2:*:*:*:*:*:*:*"}
        });
    }

    private static final boolean MATCHES = true;
    private static final boolean DOES_NOT_MATCH = false;

    private final String sourceCpe;
    private final boolean expectMatch;
    private final String targetCpe;

    public InternalAnalysisTaskCpeMatchingTest(final String sourceCpe, final boolean expectMatch, final String targetCpe) {
        this.sourceCpe = sourceCpe;
        this.expectMatch = expectMatch;
        this.targetCpe = targetCpe;
    }

    @Before
    public void setUp() {
        qm.createConfigProperty(
                SCANNER_INTERNAL_ENABLED.getGroupName(),
                SCANNER_INTERNAL_ENABLED.getPropertyName(),
                "true",
                SCANNER_INTERNAL_ENABLED.getPropertyType(),
                SCANNER_INTERNAL_ENABLED.getDescription()
        );
    }

    @Test
    public void test() throws Exception {
        final VulnerableSoftware vs = ModelConverter.convertCpe23UriToVulnerableSoftware(sourceCpe);
        vs.setVulnerable(true);
        qm.persist(vs);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-123");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setVulnerableSoftware(List.of(vs));
        qm.persist(vuln);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setCpe(targetCpe);
        qm.persist(component);

        new InternalAnalysisTask().inform(new InternalAnalysisEvent(qm.detach(Component.class, component.getId())));

        if (expectMatch) {
            assertThat(qm.getAllVulnerabilities(component)).hasSize(1);
        } else {
            assertThat(qm.getAllVulnerabilities(component)).isEmpty();
        }
    }

}
