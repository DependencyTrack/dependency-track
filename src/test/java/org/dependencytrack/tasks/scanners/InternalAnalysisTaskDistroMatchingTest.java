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
                // Red Hat
                // ---
                // Scenario: Same RHEL major version
                Arguments.of("pkg:rpm/redhat/sudo?distro=rhel-9", RANGE, MATCHES, "pkg:rpm/redhat/sudo@1.9.5?distro=rhel-9"),
                // Scenario: rhel- (Syft) vs redhat- (Trivy) prefix on same major version
                Arguments.of("pkg:rpm/redhat/sudo?distro=rhel-9", RANGE, MATCHES, "pkg:rpm/redhat/sudo@1.9.5?distro=redhat-9.7"),
                // Scenario: Point release vs major version
                Arguments.of("pkg:rpm/redhat/sudo?distro=rhel-8.6", RANGE, MATCHES, "pkg:rpm/redhat/sudo@1.9.5?distro=rhel-8"),
                // Scenario: Different RHEL major versions
                Arguments.of("pkg:rpm/redhat/sudo?distro=rhel-8", RANGE, DOES_NOT_MATCH, "pkg:rpm/redhat/sudo@1.9.5?distro=rhel-9"),
                // Scenario: VS has Red Hat distro, component does not
                Arguments.of("pkg:rpm/redhat/sudo?distro=rhel-9", RANGE, MATCHES, "pkg:rpm/redhat/sudo@1.9.5"),
                // Scenario: Distro matches but version out of range
                Arguments.of("pkg:rpm/redhat/sudo?distro=rhel-9", Range.withRange().havingEndExcluding("1.0.0"), DOES_NOT_MATCH, "pkg:rpm/redhat/sudo@1.9.5?distro=rhel-9"),
                // Scenario: Unparseable VS qualifier is not overridden by the `el` marker heuristics
                Arguments.of("pkg:rpm/redhat/libsolv?distro=garbage", Range.withRange().havingEndExcluding("0.7.30-2.el9"), MATCHES, "pkg:rpm/redhat/libsolv@0.7.24-3.el8"),
                // Scenario: Both sides have a distro qualifier, only the VS one parses
                Arguments.of("pkg:rpm/redhat/libsolv?distro=rhel-8", RANGE, DOES_NOT_MATCH, "pkg:rpm/redhat/libsolv@0.7.24-3.el8?distro=garbage"),
                // ---
                // Red Hat: `el` marker heuristics (no explicit `distro=` qualifier)
                // ---
                // Scenario: VS `el` marker on the fixed bound, component on its own version, same major
                Arguments.of("pkg:rpm/redhat/libsolv", Range.withRange().havingEndExcluding("0.7.30-2.el8"), MATCHES, "pkg:rpm/redhat/libsolv@0.7.24-3.el8"),
                // Issue:    https://github.com/DependencyTrack/dependency-track/issues/6156
                // Scenario: Satellite el8sat fixed bound vs el9 component
                Arguments.of("pkg:rpm/redhat/libsolv", Range.withRange().havingEndExcluding("1:0.7.20-6.el8sat"), DOES_NOT_MATCH, "pkg:rpm/redhat/libsolv@0.7.24-3.el9"),
                // Scenario: Component has explicit distro=rhel-8.6, VS only the fixed bound's el8
                Arguments.of("pkg:rpm/redhat/libsolv", Range.withRange().havingEndExcluding("0.7.30-2.el8"), MATCHES, "pkg:rpm/redhat/libsolv@0.7.24-3.el8?distro=rhel-8.6"),
                // Scenario: VS has explicit distro=rhel-9, component only an el8
                Arguments.of("pkg:rpm/redhat/libsolv?distro=rhel-9", RANGE, DOES_NOT_MATCH, "pkg:rpm/redhat/libsolv@0.7.24-3.el8"),
                // Scenario: Modular `el` marker on both sides, same major
                Arguments.of("pkg:rpm/redhat/php", Range.withRange().havingEndExcluding("8.0.30-3.module+el8.8.0+19602+1de75c93"), MATCHES, "pkg:rpm/redhat/php@8.0.30-2.module+el8.8.0+19602+1de75c93"),
                // Scenario: VS has modular el8 vs el9 modular component
                Arguments.of("pkg:rpm/redhat/php", Range.withRange().havingEndExcluding("8.0.30-3.module+el8.8.0+19602+1de75c93"), DOES_NOT_MATCH, "pkg:rpm/redhat/php@8.0.30-2.module+el9.2.0+12345+abcdef1"),
                // Scenario: Modular build minor differs but RHEL major matches (el8.7 vs el8.8); range decides
                Arguments.of("pkg:rpm/redhat/php", Range.withRange().havingEndExcluding("8.0.30-3.module+el8.8.0+19602+1de75c93"), MATCHES, "pkg:rpm/redhat/php@8.0.30-2.module+el8.7.0+12345+abcdef1"),
                // Scenario: Neither side carries any `el` marker; permissive "missing distro = match" default
                Arguments.of("pkg:rpm/redhat/libsolv", RANGE, MATCHES, "pkg:rpm/redhat/libsolv@1.0.0"),
                // Scenario: VS `el` marker carried by the inclusive upper bound, same major
                Arguments.of("pkg:rpm/redhat/libsolv", Range.withRange().havingEndIncluding("0.7.30-2.el8"), MATCHES, "pkg:rpm/redhat/libsolv@0.7.24-3.el8"),
                // Scenario: Inclusive upper bound el8 vs el9 component, version in range; distro rejects
                Arguments.of("pkg:rpm/redhat/libsolv", Range.withRange().havingEndIncluding("0.7.30-2.el8"), DOES_NOT_MATCH, "pkg:rpm/redhat/libsolv@0.7.24-3.el9"),
                // Scenario: VS `el` marker carried by the inclusive lower bound only
                Arguments.of("pkg:rpm/redhat/libsolv", Range.withRange().havingStartIncluding("0.7.20-1.el8"), MATCHES, "pkg:rpm/redhat/libsolv@0.7.24-3.el8"),
                // Scenario: VS `el` marker carried by the exclusive lower bound only
                Arguments.of("pkg:rpm/redhat/libsolv", Range.withRange().havingStartExcluding("0.7.20-1.el8"), MATCHES, "pkg:rpm/redhat/libsolv@0.7.24-3.el8"),
                // Issue:    https://github.com/DependencyTrack/dependency-track/issues/7938
                // Scenario: Hummingbird hum1 fixed bound vs RHEL 9 component
                Arguments.of("pkg:rpm/redhat/glibc", Range.withRange().havingEndExcluding("0:2.43-8.7.hum1"), DOES_NOT_MATCH, "pkg:rpm/redhat/glibc@2.34-284.el9_8.4?arch=x86_64&distro=redhat-9.8"),
                // Scenario: Hummingbird component as emitted by Syft vs Hummingbird VS
                Arguments.of("pkg:rpm/redhat/glibc?distro=hummingbird-1", Range.withRange().havingEndExcluding("0:2.43-8.7.hum1"), MATCHES, "pkg:rpm/redhat/glibc@2.42-11.1.hum1?arch=x86_64&distro=hummingbird-1.0"),
                // ---
                // Unsupported RPM namespace falls back to raw string comparison
                // ---
                // Scenario: Both have distro, neither parseable, same string
                Arguments.of("pkg:rpm/centos/sudo?distro=centos-9", RANGE, MATCHES, "pkg:rpm/centos/sudo@1.9.5?distro=centos-9"),
                // Scenario: Both have distro, neither parseable, different strings
                Arguments.of("pkg:rpm/centos/sudo?distro=centos-8", RANGE, DOES_NOT_MATCH, "pkg:rpm/centos/sudo@1.9.5?distro=centos-9")
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