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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class FindingAttributionTest extends PersistenceCapableTest {

    @Test
    public void testReferenceUrlTrimQueryParams() {
        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER, null, """
                https://example.com/vulnerability/INT-001\
                ?component-type=golang\
                &component-name=go.opentelemetry.io%2Fcontrib%2Finstrumentation%2Fgoogle.golang.org%2Fgrpc%2Fotelgrpc\
                &utm_source=dependency-track\
                &utm_medium=integration\
                &utm_content=v4.11.0-SNAPSHOT\
                &foo=3d48d174-0dc8-4ca5-83bb-ad697dd79b0f\
                &bar=bdf18448-0a40-4974-9758-f7b74b799395""");

        final FindingAttribution attribution = qm.getFindingAttribution(vuln, component);
        assertThat(attribution).isNotNull();
        assertThat(attribution.getReferenceUrl()).isEqualTo("https://example.com/vulnerability/INT-001");
    }

    @Test
    public void testReferenceUrlTrim() {
        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER, null, """
                https://example.com/vulnerability/foo\
                /bdf18448-0a40-4974-9758-f7b74b799395\
                /ed8e9597-321b-4a7c-a407-cf09d39960a2\
                /a6912180-f41f-4411-ae91-132d6d9cce66\
                /9f36c7fa-0137-4497-a59f-8af49f1dc30b\
                /48217aa0-06ac-4b2b-a568-cf2575920412\
                /6f641470-c5f3-4ebf-97f8-365dfd070d36\
                /11f41751-fa0b-4ee7-9689-1438f920159b\
                /fa50b01b-7de8-41e9-a84e-1ddea28a2749""");

        final FindingAttribution attribution = qm.getFindingAttribution(vuln, component);
        assertThat(attribution).isNotNull();
        assertThat(attribution.getReferenceUrl()).hasSize(255).isEqualTo("""
                https://example.com/vulnerability/foo\
                /bdf18448-0a40-4974-9758-f7b74b799395\
                /ed8e9597-321b-4a7c-a407-cf09d39960a2\
                /a6912180-f41f-4411-ae91-132d6d9cce66\
                /9f36c7fa-0137-4497-a59f-8af49f1dc30b\
                /48217aa0-06ac-4b2b-a568-cf2575920412\
                /6f641470-c5f3-4ebf-97f8-365dfd07""");
    }

}