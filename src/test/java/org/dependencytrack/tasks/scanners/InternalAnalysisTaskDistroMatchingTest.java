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
package org.dependencytrack.tasks.scanners;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.InternalAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.tasks.scanners.InternalAnalysisTaskPurlMatchingTest.Range;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED;

public class InternalAnalysisTaskDistroMatchingTest extends PersistenceCapableTest {

    private static final boolean MATCHES = true;
    private static final boolean DOES_NOT_MATCH = false;

    private static final Range RANGE = Range.withRange().havingEndExcluding("2.0.0");

    static Stream<Arguments> parameters() {
        return Stream.of(
                // ---
                // Debian
                // ---
                // Scenario: Same distro qualifier string
                Arguments.of("pkg:deb/debian/sudo?distro=debian-11", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5?distro=debian-11"),
                // Scenario: Codename vs version (semantic match)
                Arguments.of("pkg:deb/debian/sudo?distro=debian-11", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5?distro=bullseye"),
                // Scenario: Version vs codename
                Arguments.of("pkg:deb/debian/sudo?distro=bullseye", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5?distro=debian-11"),
                // Scenario: Point release vs major version
                Arguments.of("pkg:deb/debian/sudo?distro=debian-11", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5?distro=debian-11.6"),
                // Scenario: Different Debian versions
                Arguments.of("pkg:deb/debian/sudo?distro=debian-11", RANGE, DOES_NOT_MATCH, "pkg:deb/debian/sudo@1.9.5?distro=debian-12"),
                // Scenario: Different Debian codenames
                Arguments.of("pkg:deb/debian/sudo?distro=bullseye", RANGE, DOES_NOT_MATCH, "pkg:deb/debian/sudo@1.9.5?distro=bookworm"),
                // ---
                // Ubuntu
                // ---
                // Scenario: Same Ubuntu version
                Arguments.of("pkg:deb/ubuntu/sudo?distro=ubuntu-22.04", RANGE, MATCHES, "pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-22.04"),
                // Scenario: Ubuntu codename vs version
                Arguments.of("pkg:deb/ubuntu/sudo?distro=ubuntu-22.04", RANGE, MATCHES, "pkg:deb/ubuntu/sudo@1.9.5?distro=jammy"),
                // Scenario: Different Ubuntu versions
                Arguments.of("pkg:deb/ubuntu/sudo?distro=ubuntu-22.04", RANGE, DOES_NOT_MATCH, "pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-20.04"),
                // ---
                // Alpine
                // ---
                // Scenario: Same Alpine version
                Arguments.of("pkg:apk/alpine/curl?distro=alpine-3.16", RANGE, MATCHES, "pkg:apk/alpine/curl@1.0.0?distro=alpine-3.16"),
                // Scenario: Alpine point release vs major.minor
                Arguments.of("pkg:apk/alpine/curl?distro=alpine-3.16", RANGE, MATCHES, "pkg:apk/alpine/curl@1.0.0?distro=3.16.4"),
                // Scenario: Different Alpine versions
                Arguments.of("pkg:apk/alpine/curl?distro=alpine-3.16", RANGE, DOES_NOT_MATCH, "pkg:apk/alpine/curl@1.0.0?distro=alpine-3.18"),
                // ---
                // One side missing distro
                // ---
                // Scenario: VS has distro, component does not
                Arguments.of("pkg:deb/debian/sudo?distro=debian-11", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5"),
                // Scenario: Component has distro, VS does not
                Arguments.of("pkg:deb/debian/sudo", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5?distro=debian-11"),
                // Scenario: Neither has distro
                Arguments.of("pkg:deb/debian/sudo", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5"),
                // ---
                // Distro match does not bypass version check
                // ---
                // Scenario: Distro matches but version out of range
                Arguments.of("pkg:deb/debian/sudo?distro=debian-11", Range.withRange().havingEndExcluding("1.0.0"), DOES_NOT_MATCH, "pkg:deb/debian/sudo@1.9.5?distro=debian-11"),
                // ---
                // Unsupported PURL type with distro qualifiers
                // ---
                // Scenario: Both have distro, neither parseable, same string
                Arguments.of("pkg:rpm/redhat/sudo?distro=el-9", RANGE, MATCHES, "pkg:rpm/redhat/sudo@1.9.5?distro=el-9"),
                // Scenario: Both have distro, neither parseable, different strings (mismatch)
                Arguments.of("pkg:rpm/redhat/sudo?distro=rhel-9", RANGE, DOES_NOT_MATCH, "pkg:rpm/redhat/sudo@1.9.5?distro=el-9")
        );
    }

    @BeforeEach
    public void setUp() {
        qm.createConfigProperty(
                SCANNER_INTERNAL_ENABLED.getGroupName(),
                SCANNER_INTERNAL_ENABLED.getPropertyName(),
                "true",
                SCANNER_INTERNAL_ENABLED.getPropertyType(),
                SCANNER_INTERNAL_ENABLED.getDescription()
        );
    }

    @ParameterizedTest(name = "[{index}] expect={2} src={0} target={3}")
    @MethodSource("parameters")
    void test(
            String sourcePurlString,
            Range sourceRange,
            boolean expectMatch,
            String targetPurlString) throws Exception {

        final VulnerableSoftware vs = VulnerableSoftwareTestUtil.fromPurl(sourcePurlString);
        if (sourceRange != null) {
            Optional.ofNullable(sourceRange.startIncluding()).ifPresent(vs::setVersionStartIncluding);
            Optional.ofNullable(sourceRange.startExcluding()).ifPresent(vs::setVersionStartExcluding);
            Optional.ofNullable(sourceRange.endIncluding()).ifPresent(vs::setVersionEndIncluding);
            Optional.ofNullable(sourceRange.endExcluding()).ifPresent(vs::setVersionEndExcluding);
        }
        vs.setVulnerable(true);
        qm.persist(vs);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2024-0001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setVulnerableSoftware(List.of(vs));
        qm.persist(vuln);

        final var project = new Project();
        project.setName("test-project");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("test-component");
        component.setPurl(targetPurlString);
        qm.persist(component);

        new InternalAnalysisTask().inform(new InternalAnalysisEvent(
                List.of(component), VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

        if (expectMatch) {
            assertThat(qm.getAllVulnerabilities(component)).hasSize(1);
        } else {
            assertThat(qm.getAllVulnerabilities(component)).isEmpty();
        }
    }

}