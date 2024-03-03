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

import alpine.security.crypto.DataEncryption;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.TrivyAnalysisEvent;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.PullPolicy;
import org.testcontainers.utility.DockerImageName;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_TRIVY_API_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_TRIVY_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_TRIVY_ENABLED;
import static org.testcontainers.containers.wait.strategy.Wait.forLogMessage;

public class TrivyAnalysisTaskIntegrationTest extends PersistenceCapableTest {

    private static GenericContainer<?> trivyContainer;

    @BeforeClass
    @SuppressWarnings("resource")
    public static void setUpClass() {
        trivyContainer = new GenericContainer<>(DockerImageName.parse("aquasec/trivy:latest"))
                .withImagePullPolicy(PullPolicy.alwaysPull())
                .withCommand("server --listen :8080 --token TrivyToken")
                .withExposedPorts(8080)
                .waitingFor(forLogMessage(".*Listening :8080.*", 1));
        trivyContainer.start();
    }

    @Before
    public void setUp() throws Exception {
        qm.createConfigProperty(
                SCANNER_TRIVY_ENABLED.getGroupName(),
                SCANNER_TRIVY_ENABLED.getPropertyName(),
                "true",
                SCANNER_TRIVY_ENABLED.getPropertyType(),
                SCANNER_TRIVY_ENABLED.getDescription()
        );
        qm.createConfigProperty(
                SCANNER_TRIVY_BASE_URL.getGroupName(),
                SCANNER_TRIVY_BASE_URL.getPropertyName(),
                "http://localhost:%d".formatted(trivyContainer.getFirstMappedPort()),
                SCANNER_TRIVY_BASE_URL.getPropertyType(),
                SCANNER_TRIVY_BASE_URL.getDescription()
        );
        qm.createConfigProperty(
                SCANNER_TRIVY_API_TOKEN.getGroupName(),
                SCANNER_TRIVY_API_TOKEN.getPropertyName(),
                DataEncryption.encryptAsString("TrivyToken"),
                SCANNER_TRIVY_API_TOKEN.getPropertyType(),
                SCANNER_TRIVY_API_TOKEN.getDescription()
        );
    }

    @AfterClass
    public static void tearDownClass() {
        if (trivyContainer != null) {
            trivyContainer.stop();
        }
    }

    @Test
    public void test() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setGroup("com.fasterxml.woodstox");
        componentA.setName("woodstox-core");
        componentA.setVersion("5.0.0");
        componentA.setClassifier(Classifier.LIBRARY);
        componentA.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0");
        qm.persist(componentA);

        final var analysisEvent = new TrivyAnalysisEvent(List.of(componentA));
        new TrivyAnalysisTask().inform(analysisEvent);

        assertThat(qm.getAllVulnerabilities(componentA)).anySatisfy(vuln -> {
            assertThat(vuln.getVulnId()).isEqualTo("CVE-2022-40152");
            assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.NVD.name());

            // NB: Can't assert specific values here, as we're testing against
            // a moving target. These values may change over time. We do proper
            // assertions in TrivyAnalyzerTaskTest.
            assertThat(vuln.getTitle()).isNotBlank();
            assertThat(vuln.getDescription()).isNotBlank();
            assertThat(vuln.getCreated()).isNotNull();
            assertThat(vuln.getPublished()).isNotNull();
            assertThat(vuln.getUpdated()).isNotNull();
            assertThat(vuln.getCvssV3BaseScore()).isNotZero();
            assertThat(vuln.getCvssV3Vector()).isNotBlank();
            assertThat(vuln.getSeverity()).isNotNull();
            assertThat(vuln.getReferences()).isNotBlank();
        });
    }

    /**
     * This test documents the case where Trivy is unable to correlate a package with vulnerabilities
     * in its database, unless additional properties are provided. When including libc6 in an SBOM,
     * Trivy adds metadata to the component, which among other things includes alternative package names.
     * <p>
     * Here's an excerpt of the properties included:
     * <pre>
     * "properties": [
     *   {
     *     "name": "aquasecurity:trivy:LayerDiffID",
     *     "value": "sha256:256d88da41857db513b95b50ba9a9b28491b58c954e25477d5dad8abb465430b"
     *   },
     *   {
     *     "name": "aquasecurity:trivy:LayerDigest",
     *     "value": "sha256:43f89b94cd7df92a2f7e565b8fb1b7f502eff2cd225508cbd7ea2d36a9a3a601"
     *   },
     *   {
     *     "name": "aquasecurity:trivy:PkgID",
     *     "value": "libc6@2.35-0ubuntu3.4"
     *   },
     *   {
     *     "name": "aquasecurity:trivy:PkgType",
     *     "value": "ubuntu"
     *   },
     *   {
     *     "name": "aquasecurity:trivy:SrcName",
     *     "value": "glibc"
     *   },
     *   {
     *     "name": "aquasecurity:trivy:SrcRelease",
     *     "value": "0ubuntu3.4"
     *   },
     *   {
     *     "name": "aquasecurity:trivy:SrcVersion",
     *     "value": "2.35"
     *   }
     * ]
     * </pre>
     * <p>
     * To reproduce, run:
     * <pre>
     * docker run -it --rm aquasec/trivy image --format cyclonedx registry.hub.knime.com/knime/knime-full:r-5.1.2-433
     * </pre>
     *
     * @see <a href="https://github.com/DependencyTrack/dependency-track/issues/2560">Add support for CycloneDX component properties</a>
     * @see <a href="https://github.com/DependencyTrack/dependency-track/issues/3369">Support component properties with Trivy</a>
     */
    @Test
    public void testWithUnrecognizedPackageName() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("libc6");
        componentA.setVersion("2.35-0ubuntu3.4");
        componentA.setClassifier(Classifier.LIBRARY);
        componentA.setPurl("pkg:deb/ubuntu/libc6@2.35-0ubuntu3.4?arch=amd64&distro=ubuntu-22.04");
        qm.persist(componentA);

        final var analysisEvent = new TrivyAnalysisEvent(List.of(componentA));
        new TrivyAnalysisTask().inform(analysisEvent);

        assertThat(qm.getAllVulnerabilities(componentA)).isEmpty();
    }

}
