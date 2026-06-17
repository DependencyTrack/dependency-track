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
package org.dependencytrack.vulnanalysis.trivy;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateVolumeResponse;
import com.github.dockerjava.api.model.Bind;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Classification;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Property;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import java.net.http.HttpClient;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.testcontainers.containers.wait.strategy.Wait.forLogMessage;

@Disabled("Pulling Trivy images is unreliable until https://github.com/aquasecurity/trivy/discussions/10425 is fully resolved.")
class TrivyVulnAnalyzerIntegrationTest {

    private static final String LATEST_VERSION = "0.69.3";

    private static String trivyCacheVolumeName;
    private GenericContainer<?> trivyContainer;
    private TrivyVulnAnalyzer analyzer;

    static Collection<Arguments> trivyVersions() {
        return List.of(
                Arguments.of("0.51.1"), // Pre breaking change of Application#libraries -> Application#packages
                Arguments.of("0.51.2"), // Post breaking change of Application#libraries -> Application#packages
                Arguments.of(LATEST_VERSION)
        );
    }

    @BeforeAll
    @SuppressWarnings("resource")
    static void beforeAll() {
        final DockerClient dockerClient = DockerClientFactory.lazyClient();
        final CreateVolumeResponse response = dockerClient.createVolumeCmd()
                .withName("dtrack-test-trivy-cache")
                .exec();
        trivyCacheVolumeName = response.getName();
    }

    @SuppressWarnings("resource")
    private void initTrivyContainer(String trivyVersion) {
        trivyContainer = new GenericContainer<>(DockerImageName.parse("aquasec/trivy:" + trivyVersion))
                .withCommand("server --cache-dir /tmp/cache --listen :8080 --token TrivyToken")
                .withExposedPorts(8080)
                .withCreateContainerCmdModifier(cmd -> cmd.getHostConfig()
                        .withBinds(Bind.parse("%s:/tmp/cache".formatted(trivyCacheVolumeName))))
                .waitingFor(forLogMessage(".*Listening :8080.*", 1))
                .withEnv("TRIVY_DB_REPOSITORY", "public.ecr.aws/aquasecurity/trivy-db:2")
                .withEnv("TRIVY_JAVA_DB_REPOSITORY", "public.ecr.aws/aquasecurity/trivy-java-db:1");
        trivyContainer.start();

        analyzer = new TrivyVulnAnalyzer(
                HttpClient.newHttpClient(),
                "http://%s:%d".formatted(
                        trivyContainer.getHost(),
                        trivyContainer.getFirstMappedPort()),
                "TrivyToken",
                false,
                true,
                true);
    }

    @AfterEach
    void afterEach() {
        if (trivyContainer != null) {
            trivyContainer.stop();
        }
    }

    @AfterAll
    @SuppressWarnings("resource")
    static void afterAll() {
        if (trivyCacheVolumeName != null) {
            final DockerClient dockerClient = DockerClientFactory.lazyClient();
            dockerClient.removeVolumeCmd(trivyCacheVolumeName).exec();
        }
    }

    @ParameterizedTest
    @MethodSource("trivyVersions")
    void test(String trivyVersion) throws Exception {
        initTrivyContainer(trivyVersion);
        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setGroup("com.fasterxml.woodstox")
                        .setName("woodstox-core")
                        .setVersion("5.0.0")
                        .setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0")
                        .setType(Classification.CLASSIFICATION_LIBRARY)
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesList()).anySatisfy(vuln -> {
            assertThat(vuln.getId()).isEqualTo("CVE-2022-40152");
            assertThat(vuln.getSource().getName()).isEqualTo("NVD");
            assertThat(vuln.getDescription()).isNotEmpty();
        });
    }

    @ParameterizedTest
    @MethodSource("trivyVersions")
    void testWithPackageWithoutTrivyProperties(String trivyVersion) throws Exception {
        initTrivyContainer(trivyVersion);
        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("os-1")
                        .setName("ubuntu")
                        .setVersion("22.04")
                        .setType(Classification.CLASSIFICATION_OPERATING_SYSTEM)
                        .build())
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("libc6")
                        .setVersion("2.35-0ubuntu3.4")
                        .setPurl("pkg:deb/ubuntu/libc6@2.35-0ubuntu3.4?arch=amd64&distro=ubuntu-22.04")
                        .setType(Classification.CLASSIFICATION_LIBRARY)
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        // Without Trivy properties, Trivy can't correlate the package.
        assertThat(vdr.getVulnerabilitiesList()).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("trivyVersions")
    void testWithPackageWithTrivyProperties(String trivyVersion) throws Exception {
        initTrivyContainer(trivyVersion);
        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("os-1")
                        .setName("ubuntu")
                        .setVersion("22.04")
                        .setType(Classification.CLASSIFICATION_OPERATING_SYSTEM)
                        .build())
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("libc6")
                        .setVersion("2.35-0ubuntu3.4")
                        .setPurl("pkg:deb/ubuntu/libc6@2.35-0ubuntu3.4?arch=amd64&distro=ubuntu-22.04")
                        .setType(Classification.CLASSIFICATION_LIBRARY)
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:SrcName").setValue("glibc").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:SrcVersion").setValue("2.35").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:SrcRelease").setValue("0ubuntu3.4").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:PkgType").setValue("ubuntu").build())
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesList()).anySatisfy(vuln -> {
            assertThat(vuln.getId()).isEqualTo("CVE-2025-4802");
            assertThat(vuln.getSource().getName()).isEqualTo("NVD");
        });
    }

    @ParameterizedTest
    @MethodSource("trivyVersions")
    void testWithPackageWithTrivyPropertiesWithDistroWithoutOS(String trivyVersion) throws Exception {
        initTrivyContainer(trivyVersion);
        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("os-1")
                        .setName("alpine")
                        .setVersion("3.19.1")
                        .setType(Classification.CLASSIFICATION_OPERATING_SYSTEM)
                        .build())
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("git")
                        .setVersion("2.43.0-r0")
                        .setPurl("pkg:apk/alpine/git@2.43.0-r0?arch=x86_64&distro=3.19.1")
                        .setType(Classification.CLASSIFICATION_LIBRARY)
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:PkgID").setValue("git@2.43.0-r0").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:PkgType").setValue("alpine").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:SrcName").setValue("git").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:SrcVersion").setValue("2.43.0-r0").build())
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesList()).anySatisfy(vuln -> {
            assertThat(vuln.getId()).isEqualTo("CVE-2024-32002");
            assertThat(vuln.getSource().getName()).isEqualTo("NVD");
        });
    }

    @ParameterizedTest
    @MethodSource("trivyVersions")
    void testWithGoPackage(String trivyVersion) throws Exception {
        initTrivyContainer(trivyVersion);
        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("github.com/nats-io/nkeys")
                        .setVersion("0.4.4")
                        .setPurl("pkg:golang/github.com/nats-io/nkeys@0.4.4")
                        .setType(Classification.CLASSIFICATION_LIBRARY)
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesList()).hasSizeGreaterThanOrEqualTo(1);
    }

    @Test
    void testIssue5216Regression() throws Exception {
        initTrivyContainer(LATEST_VERSION);
        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("os-1")
                        .setName("amazon")
                        .setVersion("2 (Karoo)")
                        .setType(Classification.CLASSIFICATION_OPERATING_SYSTEM)
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:Class").setValue("os-pkgs").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:Type").setValue("amazon").build())
                        .build())
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("libxml2")
                        .setVersion("2.9.1-6.amzn2.5.18")
                        .setPurl("pkg:rpm/amazon/libxml2@2.9.1-6.amzn2.5.18?arch=x86_64&distro=amazon-2+%28Karoo%29")
                        .setType(Classification.CLASSIFICATION_LIBRARY)
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:PkgType").setValue("amazon").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:SrcName").setValue("libxml2").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:SrcVersion").setValue("2.9.1").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:SrcRelease").setValue("6.amzn2.5.18").build())
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesList()).hasSizeGreaterThanOrEqualTo(1);
    }

}
