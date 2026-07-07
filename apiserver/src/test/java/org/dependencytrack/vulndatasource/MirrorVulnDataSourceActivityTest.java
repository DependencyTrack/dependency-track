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
package org.dependencytrack.vulndatasource;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.cyclonedx.proto.v1_7.Bom;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.MirrorVulnDataSourceArg;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.util.ProtobufTestUtil.generateBomFromJson;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class MirrorVulnDataSourceActivityTest extends PersistenceCapableTest {

    private PluginManager pluginManager;

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    private PluginManager createPluginManager(String extensionName, VulnDataSource dataSource) {
        return createPluginManager(List.of(
                new TestVulnDataSourceFactory(extensionName, () -> dataSource)));
    }

    private PluginManager createPluginManager(List<VulnDataSourceFactory> factories) {
        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                _ -> null,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                List.of(VulnDataSource.class));
        pluginManager.loadPlugins(List.of(() -> List.copyOf(factories)));
        return pluginManager;
    }

    @Test
    void shouldThrowWhenExtensionNotFound() {
        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                _ -> null,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                List.of(VulnDataSource.class));
        pluginManager.loadPlugins(List.of());

        final var activity = new MirrorVulnDataSourceActivity(pluginManager);
        final var arg = MirrorVulnDataSourceArg.newBuilder()
                .setDataSourceName("nonexistent")
                .setSourceName("NVD")
                .build();

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> activity.execute(mock(ActivityContext.class), arg));
    }

    @Test
    void shouldThrowWhenExtensionDisabled() {
        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                _ -> null,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                List.of(VulnDataSource.class));
        pluginManager.loadPlugins(List.of(
                () -> List.of(new DisabledVulnDataSourceFactory("nvd"))));

        final var activity = new MirrorVulnDataSourceActivity(pluginManager);
        final var arg = MirrorVulnDataSourceArg.newBuilder()
                .setDataSourceName("nvd")
                .setSourceName("NVD")
                .build();

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> activity.execute(mock(ActivityContext.class), arg));
    }

    @Test
    void shouldThrowWhenSourceNameInvalid() {
        final var dataSourceMock = mock(VulnDataSource.class);
        final var activity = new MirrorVulnDataSourceActivity(createPluginManager("nvd", dataSourceMock));
        final var arg = MirrorVulnDataSourceArg.newBuilder()
                .setDataSourceName("nvd")
                .setSourceName("INVALID")
                .build();

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> activity.execute(mock(ActivityContext.class), arg));
    }

    @Test
    void shouldNotOverwriteExistingVulnWhenAuthoritativeMirrorEnabled() throws Exception {
        final var existing = new Vulnerability();
        existing.setVulnId("GHSA-fxwm-579q-49qq");
        existing.setSource(Vulnerability.Source.GITHUB);
        existing.setDescription("Authoritative GHSA description");
        qm.createVulnerability(existing);

        final var bovJson = """
                {
                  "vulnerabilities": [
                    {
                      "id": "GHSA-fxwm-579q-49qq",
                      "source": { "name": "GITHUB" },
                      "description": "Republished by OSV."
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var osvDataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(osvDataSourceMock).hasNext();
        doReturn(bov).when(osvDataSourceMock).next();

        final var pluginManager = createPluginManager(List.of(
                new TestVulnDataSourceFactory("osv", () -> osvDataSourceMock),
                new TestVulnDataSourceFactory("github", () -> mock(VulnDataSource.class))));

        final var activity = new MirrorVulnDataSourceActivity(pluginManager);
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder()
                .setDataSourceName("osv").setSourceName("OSV").build());

        verify(osvDataSourceMock).markProcessed(eq(bov));
        final Vulnerability vuln = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-fxwm-579q-49qq");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getDescription()).isEqualTo("Authoritative GHSA description");
    }

    @Test
    void shouldCreateMissingVulnWhenAuthoritativeMirrorEnabled() throws Exception {
        final var bovJson = """
                {
                  "vulnerabilities": [
                    {
                      "id": "GHSA-fxwm-579q-49qq",
                      "source": { "name": "GITHUB" },
                      "description": "Republished by OSV."
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var osvDataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(osvDataSourceMock).hasNext();
        doReturn(bov).when(osvDataSourceMock).next();

        final var pluginManager = createPluginManager(List.of(
                new TestVulnDataSourceFactory("osv", () -> osvDataSourceMock),
                new TestVulnDataSourceFactory("github", () -> mock(VulnDataSource.class))));

        final var activity = new MirrorVulnDataSourceActivity(pluginManager);
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder()
                .setDataSourceName("osv").setSourceName("OSV").build());

        verify(osvDataSourceMock).markProcessed(eq(bov));
        final Vulnerability vuln = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-fxwm-579q-49qq");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getDescription()).isEqualTo("Republished by OSV.");
    }

    @Test
    void shouldProcessBovWhenAuthoritativeMirrorAbsent() throws Exception {
        final var bovJson = """
                {
                  "vulnerabilities": [
                    {
                      "id": "GHSA-fxwm-579q-49qq",
                      "source": { "name": "GITHUB" },
                      "description": "Republished by OSV."
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var osvDataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(osvDataSourceMock).hasNext();
        doReturn(bov).when(osvDataSourceMock).next();

        final var pluginManager = createPluginManager(List.of(
                new TestVulnDataSourceFactory("osv", () -> osvDataSourceMock)));

        final var activity = new MirrorVulnDataSourceActivity(pluginManager);
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder()
                .setDataSourceName("osv").setSourceName("OSV").build());

        verify(osvDataSourceMock).markProcessed(eq(bov));
        assertThat(qm.getVulnerabilityByVulnId("GITHUB", "GHSA-fxwm-579q-49qq")).isNotNull();
    }

    @Test
    void shouldSkipBovFromInternalSource() throws Exception {
        final var bovJson = """
                {
                  "vulnerabilities": [
                    {
                      "id": "INT-001",
                      "source": { "name": "INTERNAL" },
                      "description": "Should never be overwritten by a mirror."
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var osvDataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(osvDataSourceMock).hasNext();
        doReturn(bov).when(osvDataSourceMock).next();

        final var activity = new MirrorVulnDataSourceActivity(createPluginManager("osv", osvDataSourceMock));
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder()
                .setDataSourceName("osv").setSourceName("OSV").build());

        verify(osvDataSourceMock).markProcessed(eq(bov));
        assertThat(qm.getVulnerabilityByVulnId("INTERNAL", "INT-001")).isNull();
    }

    @Test
    void shouldProcessNvdVuln() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "02cd44fb-2f0a-569b-a508-1e179e123e38",
                      "type": "CLASSIFICATION_APPLICATION",
                      "publisher": "thinkcmf",
                      "name": "thinkcmf",
                      "cpe": "cpe:2.3:a:thinkcmf:thinkcmf:6.0.7:*:*:*:*:*:*:*"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "CVE-2022-40489",
                      "source": { "name": "NVD" },
                      "description": "ThinkCMF version 6.0.7 is affected by a",
                      "cwes": [ 352 ],
                      "published": "2022-12-01T05:15:11Z",
                      "updated": "2022-12-02T17:17:02Z",
                      "ratings": [
                        {
                          "method": "SCORE_METHOD_CVSSV31",
                          "score": 8.8,
                          "severity": "SEVERITY_HIGH",
                          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                          "source": { "name": "NVD" }
                        }
                      ],
                      "affects": [
                        {
                          "ref": "02cd44fb-2f0a-569b-a508-1e179e123e38",
                          "versions": [
                            { "version": "6.0.7" }
                          ]
                        }
                      ]
                    }
                  ],
                  "externalReferences": [
                    { "url": "https://github.com/thinkcmf/thinkcmf/issues/736" }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        final var activity = new MirrorVulnDataSourceActivity(createPluginManager("nvd", dataSourceMock));
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder().setDataSourceName("nvd").setSourceName("NVD").build());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("NVD", "CVE-2022-40489");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("CVE-2022-40489");
        assertThat(vuln.getFriendlyVulnId()).isNull();
        assertThat(vuln.getSource()).isEqualTo("NVD");
        assertThat(vuln.getTitle()).isNull();
        assertThat(vuln.getSubTitle()).isNull();
        assertThat(vuln.getDescription()).isEqualTo("ThinkCMF version 6.0.7 is affected by a");
        assertThat(vuln.getDetail()).isNull();
        assertThat(vuln.getRecommendation()).isNull();
        assertThat(vuln.getCwes()).containsOnly(352);
        assertThat(vuln.getCreated()).isNull();
        assertThat(vuln.getPublished()).isEqualTo("2022-12-01T05:15:11Z");
        assertThat(vuln.getUpdated()).isEqualTo("2022-12-02T17:17:02Z");
        assertThat(vuln.getCvssV2Vector()).isNull();
        assertThat(vuln.getCvssV2BaseScore()).isNull();
        assertThat(vuln.getCvssV2ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
        assertThat(vuln.getCvssV3BaseScore()).isEqualTo("8.8");
        assertThat(vuln.getCvssV3ImpactSubScore()).isEqualTo("5.9");
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isEqualTo("2.8");
        assertThat(vuln.getOwaspRRVector()).isNull();
        assertThat(vuln.getOwaspRRLikelihoodScore()).isNull();
        assertThat(vuln.getOwaspRRBusinessImpactScore()).isNull();
        assertThat(vuln.getOwaspRRTechnicalImpactScore()).isNull();
        assertThat(vuln.getSeverity()).isEqualTo(Severity.HIGH);
        assertThat(vuln.getReferences()).isEqualTo("""
                * [https://github.com/thinkcmf/thinkcmf/issues/736](https://github.com/thinkcmf/thinkcmf/issues/736)
                """);
        assertThat(vuln.getCredits()).isNull();
        assertThat(vuln.getVulnerableVersions()).isNull();
        assertThat(vuln.getPatchedVersions()).isNull();

        assertThat(vuln.getVulnerableSoftware()).satisfiesExactly(vs -> {
            assertThat(vs.getCpe22()).isEqualTo("cpe:/a:thinkcmf:thinkcmf:6.0.7");
            assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:thinkcmf:thinkcmf:6.0.7:*:*:*:*:*:*:*");
            assertThat(vs.getPart()).isEqualTo("a");
            assertThat(vs.getVendor()).isEqualTo("thinkcmf");
            assertThat(vs.getProduct()).isEqualTo("thinkcmf");
            assertThat(vs.getVersion()).isEqualTo("6.0.7");
            assertThat(vs.getUpdate()).isEqualTo("*");
            assertThat(vs.getEdition()).isEqualTo("*");
            assertThat(vs.getLanguage()).isEqualTo("*");
            assertThat(vs.getSwEdition()).isEqualTo("*");
            assertThat(vs.getTargetSw()).isEqualTo("*");
            assertThat(vs.getTargetHw()).isEqualTo("*");
            assertThat(vs.getOther()).isEqualTo("*");
            assertThat(vs.getVersionStartIncluding()).isNull();
            assertThat(vs.getVersionStartExcluding()).isNull();
            assertThat(vs.getVersionEndIncluding()).isNull();
            assertThat(vs.getVersionEndExcluding()).isNull();
            assertThat(vs.isVulnerable()).isTrue();
            assertThat(vs.getPurlType()).isNull();
            assertThat(vs.getPurlNamespace()).isNull();
            assertThat(vs.getPurlName()).isNull();
            assertThat(vs.getPurlVersion()).isNull();
            assertThat(vs.getPurlQualifiers()).isNull();
            assertThat(vs.getPurlSubpath()).isNull();
            assertThat(vs.getPurl()).isNull();
        });
    }

    @Test
    void shouldProcessRejectedVuln() throws Exception {
        final var bovJson = /* language=JSON */ """
                {
                  "vulnerabilities": [
                    {
                      "id": "CVE-2022-40489",
                      "source": { "name": "NVD" },
                      "rejected": "2022-12-05T10:15:00Z"
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        final var activity = new MirrorVulnDataSourceActivity(createPluginManager("nvd", dataSourceMock));
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder()
                .setDataSourceName("nvd").setSourceName("NVD").build());

        verify(dataSourceMock).markProcessed(eq(bov));
        final Vulnerability vuln = qm.getVulnerabilityByVulnId("NVD", "CVE-2022-40489");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getRejected()).isEqualTo("2022-12-05T10:15:00Z");
    }

    @Test
    void shouldProcessGitHubVuln() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "3c41e06b-5923-5392-a1e3-64a630c97591",
                      "purl": "pkg:nuget/bootstrap"
                    },
                    {
                      "bomRef": "e5dc290a-c649-5f73-b814-c9a47690a48a",
                      "purl": "pkg:nuget/bootstrap.sass"
                    },
                    {
                      "bomRef": "c8e5d671-0b0d-5fda-a404-730615325a7f",
                      "purl": "pkg:nuget/Bootstrap.Less"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "GHSA-fxwm-579q-49qq",
                      "source": { "name": "GITHUB" },
                      "description": "In Bootstrap 4 before 4.3.1 and Bootstrap 3 before 3.4.1,",
                      "properties": [
                          {
                            "name": "dependency-track:vuln:title",
                            "value": "Moderate severity vulnerability that affects Bootstrap.Less, bootstrap, and bootstrap.sass"
                          }
                      ],
                      "published": "2019-02-22T20:54:40Z",
                      "updated": "2021-12-03T14:54:43Z",
                      "ratings": [
                        {
                          "method": "SCORE_METHOD_OTHER",
                          "severity": "SEVERITY_MEDIUM",
                          "source": { "name": "GITHUB" }
                        }
                      ],
                      "affects": [
                        {
                          "ref": "3c41e06b-5923-5392-a1e3-64a630c97591",
                          "versions": [
                            { "range": "vers:nuget/>= 3.0.0|< 3.4.1" },
                            { "range": "vers:nuget/>= 4.0.0|< 4.3.1" }
                          ]
                        },
                        {
                          "ref": "e5dc290a-c649-5f73-b814-c9a47690a48a",
                          "versions": [
                            { "range": "vers:nuget/< 4.3.1" }
                          ]
                        },
                        {
                          "ref": "c8e5d671-0b0d-5fda-a404-730615325a7f",
                          "versions": [
                            { "range": "vers:nuget/>= 3.0.0|< 3.4.1" }
                          ]
                        }
                      ]
                    }
                  ],
                  "externalReferences": [
                    { "url": "https://github.com/advisories/GHSA-fxwm-579q-49qq" }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        final var activity = new MirrorVulnDataSourceActivity(createPluginManager("github", dataSourceMock));
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder().setDataSourceName("github").setSourceName("GITHUB").build());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-fxwm-579q-49qq");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("GHSA-fxwm-579q-49qq");
        assertThat(vuln.getFriendlyVulnId()).isNull();
        assertThat(vuln.getSource()).isEqualTo("GITHUB");
        assertThat(vuln.getTitle()).isEqualTo("Moderate severity vulnerability that affects Bootstrap.Less, bootstrap, and bootstrap.sass");
        assertThat(vuln.getSubTitle()).isNull();
        assertThat(vuln.getDescription()).isEqualTo("In Bootstrap 4 before 4.3.1 and Bootstrap 3 before 3.4.1,");
        assertThat(vuln.getDetail()).isNull();
        assertThat(vuln.getRecommendation()).isNull();
        assertThat(vuln.getCwes()).isNull();
        assertThat(vuln.getCreated()).isNull();
        assertThat(vuln.getPublished()).isEqualTo("2019-02-22T20:54:40Z");
        assertThat(vuln.getUpdated()).isEqualTo("2021-12-03T14:54:43Z");
        assertThat(vuln.getCvssV2Vector()).isNull();
        assertThat(vuln.getCvssV2BaseScore()).isNull();
        assertThat(vuln.getCvssV2ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3Vector()).isNull();
        assertThat(vuln.getCvssV3BaseScore()).isNull();
        assertThat(vuln.getCvssV3ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNull();
        assertThat(vuln.getOwaspRRVector()).isNull();
        assertThat(vuln.getOwaspRRLikelihoodScore()).isNull();
        assertThat(vuln.getOwaspRRBusinessImpactScore()).isNull();
        assertThat(vuln.getOwaspRRTechnicalImpactScore()).isNull();
        assertThat(vuln.getSeverity()).isEqualTo(Severity.MEDIUM);
        assertThat(vuln.getReferences()).isEqualTo("""
                * [https://github.com/advisories/GHSA-fxwm-579q-49qq](https://github.com/advisories/GHSA-fxwm-579q-49qq)
                """);
        assertThat(vuln.getCredits()).isNull();
        assertThat(vuln.getVulnerableVersions()).isNull();
        assertThat(vuln.getPatchedVersions()).isNull();

        assertThat(vuln.getVulnerableSoftware()).satisfiesExactlyInAnyOrder(
                vs -> {
                    assertThat(vs.getCpe22()).isNull();
                    assertThat(vs.getCpe23()).isNull();
                    assertThat(vs.getPart()).isNull();
                    assertThat(vs.getVendor()).isNull();
                    assertThat(vs.getProduct()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getUpdate()).isNull();
                    assertThat(vs.getEdition()).isNull();
                    assertThat(vs.getLanguage()).isNull();
                    assertThat(vs.getSwEdition()).isNull();
                    assertThat(vs.getTargetSw()).isNull();
                    assertThat(vs.getTargetHw()).isNull();
                    assertThat(vs.getOther()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("3.0.0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("3.4.1");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isEqualTo("nuget");
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isEqualTo("bootstrap");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isEqualTo("pkg:nuget/bootstrap");
                },
                vs -> {
                    assertThat(vs.getCpe22()).isNull();
                    assertThat(vs.getCpe23()).isNull();
                    assertThat(vs.getPart()).isNull();
                    assertThat(vs.getVendor()).isNull();
                    assertThat(vs.getProduct()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getUpdate()).isNull();
                    assertThat(vs.getEdition()).isNull();
                    assertThat(vs.getLanguage()).isNull();
                    assertThat(vs.getSwEdition()).isNull();
                    assertThat(vs.getTargetSw()).isNull();
                    assertThat(vs.getTargetHw()).isNull();
                    assertThat(vs.getOther()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("4.0.0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("4.3.1");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isEqualTo("nuget");
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isEqualTo("bootstrap");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isEqualTo("pkg:nuget/bootstrap");
                },
                vs -> {
                    assertThat(vs.getCpe22()).isNull();
                    assertThat(vs.getCpe23()).isNull();
                    assertThat(vs.getPart()).isNull();
                    assertThat(vs.getVendor()).isNull();
                    assertThat(vs.getProduct()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getUpdate()).isNull();
                    assertThat(vs.getEdition()).isNull();
                    assertThat(vs.getLanguage()).isNull();
                    assertThat(vs.getSwEdition()).isNull();
                    assertThat(vs.getTargetSw()).isNull();
                    assertThat(vs.getTargetHw()).isNull();
                    assertThat(vs.getOther()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("4.3.1");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isEqualTo("nuget");
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isEqualTo("bootstrap.sass");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isEqualTo("pkg:nuget/bootstrap.sass");
                },
                vs -> {
                    assertThat(vs.getCpe22()).isNull();
                    assertThat(vs.getCpe23()).isNull();
                    assertThat(vs.getPart()).isNull();
                    assertThat(vs.getVendor()).isNull();
                    assertThat(vs.getProduct()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getUpdate()).isNull();
                    assertThat(vs.getEdition()).isNull();
                    assertThat(vs.getLanguage()).isNull();
                    assertThat(vs.getSwEdition()).isNull();
                    assertThat(vs.getTargetSw()).isNull();
                    assertThat(vs.getTargetHw()).isNull();
                    assertThat(vs.getOther()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("3.0.0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("3.4.1");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isEqualTo("nuget");
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isEqualTo("Bootstrap.Less");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isEqualTo("pkg:nuget/Bootstrap.Less");
                }
        );
    }

    @Test
    void shouldProcessOsvVuln() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "2a24a29f-9ff3-52b8-bc81-471f326a5b3e",
                      "name": "io.ratpack:ratpack-session",
                      "purl": "pkg:maven/io.ratpack/ratpack-session"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "GHSA-2cc5-23r7-vc4v",
                      "source": { "name": "GITHUB" },
                      "description": "### Impact",
                      "cwes": [ 330, 340 ],
                      "published": "2021-07-01T17:02:26Z",
                      "updated": "2023-03-28T05:45:27Z",
                      "ratings": [
                        {
                          "method": "SCORE_METHOD_CVSSV3",
                          "score": 4.4,
                          "severity": "SEVERITY_MEDIUM",
                          "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
                        }
                      ],
                      "advisories": [
                        { "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-29480" }
                      ],
                      "properties": [
                          {
                            "name": "dependency-track:vuln:title",
                            "value": "Ratpack's default client side session signing key is highly predictable"
                          }
                      ],
                      "affects": [
                        {
                          "ref": "2a24a29f-9ff3-52b8-bc81-471f326a5b3e",
                          "versions": [
                            { "range": "vers:maven/>=0|<1.9.0" },
                            { "version": "0.9.0" },
                            { "version": "0.9.1" }
                          ]
                        }
                      ]
                    }
                  ],
                  "externalReferences": [
                    { "url": "https://github.com/ratpack/ratpack/security/advisories/GHSA-2cc5-23r7-vc4v" },
                    { "url": "https://github.com/ratpack/ratpack" },
                    { "url": "https://github.com/ratpack/ratpack/blob/29434f7ac6fd4b36a4495429b70f4c8163100332/ratpack-session/src/main/java/ratpack/session/clientside/ClientSideSessionConfig.java#L29" }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        final var activity = new MirrorVulnDataSourceActivity(createPluginManager("osv", dataSourceMock));
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder().setDataSourceName("osv").setSourceName("OSV").build());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-2cc5-23r7-vc4v");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("GHSA-2cc5-23r7-vc4v");
        assertThat(vuln.getFriendlyVulnId()).isNull();
        assertThat(vuln.getSource()).isEqualTo("GITHUB");
        assertThat(vuln.getTitle()).isEqualTo("Ratpack's default client side session signing key is highly predictable");
        assertThat(vuln.getSubTitle()).isNull();
        assertThat(vuln.getDescription()).isEqualTo("### Impact");
        assertThat(vuln.getDetail()).isNull();
        assertThat(vuln.getRecommendation()).isNull();
        assertThat(vuln.getCwes()).containsOnly(330, 340);
        assertThat(vuln.getCreated()).isNull();
        assertThat(vuln.getPublished()).isEqualTo("2021-07-01T17:02:26Z");
        assertThat(vuln.getUpdated()).isEqualTo("2023-03-28T05:45:27Z");
        assertThat(vuln.getCvssV2Vector()).isNull();
        assertThat(vuln.getCvssV2BaseScore()).isNull();
        assertThat(vuln.getCvssV2ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
        assertThat(vuln.getCvssV3BaseScore()).isEqualTo("4.4");
        assertThat(vuln.getCvssV3ImpactSubScore()).isEqualTo("2.5");
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isEqualTo("1.8");
        assertThat(vuln.getOwaspRRVector()).isNull();
        assertThat(vuln.getOwaspRRLikelihoodScore()).isNull();
        assertThat(vuln.getOwaspRRBusinessImpactScore()).isNull();
        assertThat(vuln.getOwaspRRTechnicalImpactScore()).isNull();
        assertThat(vuln.getSeverity()).isEqualTo(Severity.MEDIUM);
        assertThat(vuln.getReferences()).isEqualTo("""
                * [https://github.com/ratpack/ratpack/security/advisories/GHSA-2cc5-23r7-vc4v](https://github.com/ratpack/ratpack/security/advisories/GHSA-2cc5-23r7-vc4v)
                * [https://github.com/ratpack/ratpack](https://github.com/ratpack/ratpack)
                * [https://github.com/ratpack/ratpack/blob/29434f7ac6fd4b36a4495429b70f4c8163100332/ratpack-session/src/main/java/ratpack/session/clientside/ClientSideSessionConfig.java#L29](https://github.com/ratpack/ratpack/blob/29434f7ac6fd4b36a4495429b70f4c8163100332/ratpack-session/src/main/java/ratpack/session/clientside/ClientSideSessionConfig.java#L29)
                * [https://nvd.nist.gov/vuln/detail/CVE-2021-29480](https://nvd.nist.gov/vuln/detail/CVE-2021-29480)
                """);
        assertThat(vuln.getCredits()).isNull();
        assertThat(vuln.getVulnerableVersions()).isNull();
        assertThat(vuln.getPatchedVersions()).isNull();

        assertThat(vuln.getVulnerableSoftware()).satisfiesExactlyInAnyOrder(
                vs -> {
                    assertThat(vs.getCpe22()).isNull();
                    assertThat(vs.getCpe23()).isNull();
                    assertThat(vs.getPart()).isNull();
                    assertThat(vs.getVendor()).isNull();
                    assertThat(vs.getProduct()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getUpdate()).isNull();
                    assertThat(vs.getEdition()).isNull();
                    assertThat(vs.getLanguage()).isNull();
                    assertThat(vs.getSwEdition()).isNull();
                    assertThat(vs.getTargetSw()).isNull();
                    assertThat(vs.getTargetHw()).isNull();
                    assertThat(vs.getOther()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("1.9.0");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isEqualTo("maven");
                    assertThat(vs.getPurlNamespace()).isEqualTo("io.ratpack");
                    assertThat(vs.getPurlName()).isEqualTo("ratpack-session");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isEqualTo("pkg:maven/io.ratpack/ratpack-session");
                },
                vs -> {
                    assertThat(vs.getCpe22()).isNull();
                    assertThat(vs.getCpe23()).isNull();
                    assertThat(vs.getPart()).isNull();
                    assertThat(vs.getVendor()).isNull();
                    assertThat(vs.getProduct()).isNull();
                    assertThat(vs.getVersion()).isEqualTo("0.9.0");
                    assertThat(vs.getUpdate()).isNull();
                    assertThat(vs.getEdition()).isNull();
                    assertThat(vs.getLanguage()).isNull();
                    assertThat(vs.getSwEdition()).isNull();
                    assertThat(vs.getTargetSw()).isNull();
                    assertThat(vs.getTargetHw()).isNull();
                    assertThat(vs.getOther()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isNull();
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isEqualTo("maven");
                    assertThat(vs.getPurlNamespace()).isEqualTo("io.ratpack");
                    assertThat(vs.getPurlName()).isEqualTo("ratpack-session");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isEqualTo("pkg:maven/io.ratpack/ratpack-session");
                },
                vs -> {
                    assertThat(vs.getCpe22()).isNull();
                    assertThat(vs.getCpe23()).isNull();
                    assertThat(vs.getPart()).isNull();
                    assertThat(vs.getVendor()).isNull();
                    assertThat(vs.getProduct()).isNull();
                    assertThat(vs.getVersion()).isEqualTo("0.9.1");
                    assertThat(vs.getUpdate()).isNull();
                    assertThat(vs.getEdition()).isNull();
                    assertThat(vs.getLanguage()).isNull();
                    assertThat(vs.getSwEdition()).isNull();
                    assertThat(vs.getTargetSw()).isNull();
                    assertThat(vs.getTargetHw()).isNull();
                    assertThat(vs.getOther()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isNull();
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isEqualTo("maven");
                    assertThat(vs.getPurlNamespace()).isEqualTo("io.ratpack");
                    assertThat(vs.getPurlName()).isEqualTo("ratpack-session");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isEqualTo("pkg:maven/io.ratpack/ratpack-session");
                }
        );
    }

    @Test
    void shouldProcessVulnWithoutAffects() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "02cd44fb-2f0a-569b-a508-1e179e123e38",
                      "type": "CLASSIFICATION_APPLICATION",
                      "publisher": "thinkcmf",
                      "name": "thinkcmf",
                      "cpe": "cpe:2.3:a:thinkcmf:thinkcmf:6.0.7:*:*:*:*:*:*:*"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "CVE-2022-40489",
                      "source": { "name": "NVD" }
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        final var activity = new MirrorVulnDataSourceActivity(createPluginManager("nvd", dataSourceMock));
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder().setDataSourceName("nvd").setSourceName("NVD").build());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("NVD", "CVE-2022-40489");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("CVE-2022-40489");
        assertThat(vuln.getFriendlyVulnId()).isNull();
        assertThat(vuln.getSource()).isEqualTo("NVD");
        assertThat(vuln.getTitle()).isNull();
        assertThat(vuln.getSubTitle()).isNull();
        assertThat(vuln.getDescription()).isNull();
        assertThat(vuln.getDetail()).isNull();
        assertThat(vuln.getRecommendation()).isNull();
        assertThat(vuln.getCwes()).isNull();
        assertThat(vuln.getCreated()).isNull();
        assertThat(vuln.getPublished()).isNull();
        assertThat(vuln.getUpdated()).isNull();
        assertThat(vuln.getCvssV2Vector()).isNull();
        assertThat(vuln.getCvssV2BaseScore()).isNull();
        assertThat(vuln.getCvssV2ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3Vector()).isNull();
        assertThat(vuln.getCvssV3BaseScore()).isNull();
        assertThat(vuln.getCvssV3ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNull();
        assertThat(vuln.getOwaspRRVector()).isNull();
        assertThat(vuln.getOwaspRRLikelihoodScore()).isNull();
        assertThat(vuln.getOwaspRRBusinessImpactScore()).isNull();
        assertThat(vuln.getOwaspRRTechnicalImpactScore()).isNull();
        assertThat(vuln.getSeverity()).isEqualTo(Severity.UNASSIGNED);
        assertThat(vuln.getReferences()).isNull();
        assertThat(vuln.getCredits()).isNull();
        assertThat(vuln.getVulnerableVersions()).isNull();
        assertThat(vuln.getPatchedVersions()).isNull();
        assertThat(vuln.getVulnerableSoftware()).isEmpty();
    }

    @Test
    void shouldProcessVulnWithUnmatchedAffectsBomRef() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "9828f8e4-b24d-429c-b14b-a426a42785dc",
                      "type": "CLASSIFICATION_APPLICATION",
                      "publisher": "thinkcmf",
                      "name": "thinkcmf",
                      "cpe": "cpe:2.3:a:thinkcmf:thinkcmf:6.0.7:*:*:*:*:*:*:*"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "CVE-2022-40489",
                      "source": { "name": "NVD" },
                      "affects": [
                        {
                          "ref": "02cd44fb-2f0a-569b-a508-1e179e123e38",
                          "versions": [
                            { "version": "6.0.7" }
                          ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        final var activity = new MirrorVulnDataSourceActivity(createPluginManager("nvd", dataSourceMock));
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder().setDataSourceName("nvd").setSourceName("NVD").build());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("NVD", "CVE-2022-40489");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("CVE-2022-40489");
        assertThat(vuln.getFriendlyVulnId()).isNull();
        assertThat(vuln.getSource()).isEqualTo("NVD");
        assertThat(vuln.getTitle()).isNull();
        assertThat(vuln.getSubTitle()).isNull();
        assertThat(vuln.getDescription()).isNull();
        assertThat(vuln.getDetail()).isNull();
        assertThat(vuln.getRecommendation()).isNull();
        assertThat(vuln.getCwes()).isNull();
        assertThat(vuln.getCreated()).isNull();
        assertThat(vuln.getPublished()).isNull();
        assertThat(vuln.getUpdated()).isNull();
        assertThat(vuln.getCvssV2Vector()).isNull();
        assertThat(vuln.getCvssV2BaseScore()).isNull();
        assertThat(vuln.getCvssV2ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3Vector()).isNull();
        assertThat(vuln.getCvssV3BaseScore()).isNull();
        assertThat(vuln.getCvssV3ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNull();
        assertThat(vuln.getOwaspRRVector()).isNull();
        assertThat(vuln.getOwaspRRLikelihoodScore()).isNull();
        assertThat(vuln.getOwaspRRBusinessImpactScore()).isNull();
        assertThat(vuln.getOwaspRRTechnicalImpactScore()).isNull();
        assertThat(vuln.getSeverity()).isEqualTo(Severity.UNASSIGNED);
        assertThat(vuln.getReferences()).isNull();
        assertThat(vuln.getCredits()).isNull();
        assertThat(vuln.getVulnerableVersions()).isNull();
        assertThat(vuln.getPatchedVersions()).isNull();
        assertThat(vuln.getVulnerableSoftware()).isEmpty();
    }

    @Test
    void shouldProcessVulnWithVersConstraints() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "02cd44fb-2f0a-569b-a508-1e179e123e38",
                      "type": "CLASSIFICATION_APPLICATION",
                      "publisher": "thinkcmf",
                      "name": "thinkcmf",
                      "cpe": "cpe:2.3:a:thinkcmf:thinkcmf:*:*:*:*:*:*:*:*"
                    },
                    {
                      "bomRef": "ed08bfc7-e88a-4647-bb2a-cad271aec5cc",
                      "purl": "pkg:maven/com.example/foo"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "CVE-2022-40489",
                      "source": { "name": "NVD" },
                      "affects": [
                        {
                          "ref": "02cd44fb-2f0a-569b-a508-1e179e123e38",
                          "versions": [
                            { "range": null },
                            { "range": "" },
                            { "range": "<999" },
                            { "range": "vers:" },
                            { "range": "vers:foobar/<1" },
                            { "range": "vers:generic/*" },
                            { "range": "vers:generic/0" },
                            { "range": "vers:generic/>0" },
                            { "range": "vers:generic/1" },
                            { "range": "vers:generic/>2" },
                            { "range": "vers:generic/>3|< 4" },
                            { "range": "vers:generic/>5|<6|6.0.1" },
                            { "range": "vers:generic/>*|<7" },
                            { "range": "vers:generic/>8" },
                            { "range": "vers:generic/>9|>=10" },
                            { "range": "vers:generic/<11|<=12" },
                            { "range": "vers:generic/<13" }
                          ]
                        },
                        {
                          "ref": "ed08bfc7-e88a-4647-bb2a-cad271aec5cc",
                          "versions": [
                            { "range": "vers:generic/*" }
                          ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        final var activity = new MirrorVulnDataSourceActivity(createPluginManager("nvd", dataSourceMock));
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder().setDataSourceName("nvd").setSourceName("NVD").build());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("NVD", "CVE-2022-40489");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("CVE-2022-40489");
        assertThat(vuln.getFriendlyVulnId()).isNull();
        assertThat(vuln.getSource()).isEqualTo("NVD");
        assertThat(vuln.getTitle()).isNull();
        assertThat(vuln.getSubTitle()).isNull();
        assertThat(vuln.getDescription()).isNull();
        assertThat(vuln.getDetail()).isNull();
        assertThat(vuln.getRecommendation()).isNull();
        assertThat(vuln.getCwes()).isNull();
        assertThat(vuln.getCreated()).isNull();
        assertThat(vuln.getPublished()).isNull();
        assertThat(vuln.getUpdated()).isNull();
        assertThat(vuln.getCvssV2Vector()).isNull();
        assertThat(vuln.getCvssV2BaseScore()).isNull();
        assertThat(vuln.getCvssV2ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3Vector()).isNull();
        assertThat(vuln.getCvssV3BaseScore()).isNull();
        assertThat(vuln.getCvssV3ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNull();
        assertThat(vuln.getOwaspRRVector()).isNull();
        assertThat(vuln.getOwaspRRLikelihoodScore()).isNull();
        assertThat(vuln.getOwaspRRBusinessImpactScore()).isNull();
        assertThat(vuln.getOwaspRRTechnicalImpactScore()).isNull();
        assertThat(vuln.getSeverity()).isEqualTo(Severity.UNASSIGNED);
        assertThat(vuln.getReferences()).isNull();
        assertThat(vuln.getCredits()).isNull();
        assertThat(vuln.getVulnerableVersions()).isNull();
        assertThat(vuln.getPatchedVersions()).isNull();

        assertThat(vuln.getVulnerableSoftware()).satisfiesExactlyInAnyOrder(
                // vers:foobar/<1
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/a:thinkcmf:thinkcmf");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:thinkcmf:thinkcmf:*:*:*:*:*:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("thinkcmf");
                    assertThat(vs.getProduct()).isEqualTo("thinkcmf");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("*");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("1");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isNull();
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isNull();
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isNull();
                },
                // vers:generic/*
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/a:thinkcmf:thinkcmf");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:thinkcmf:thinkcmf:*:*:*:*:*:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("thinkcmf");
                    assertThat(vs.getProduct()).isEqualTo("thinkcmf");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("*");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isNull();
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isNull();
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isNull();
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isNull();
                },
                // vers:generic/>0
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/a:thinkcmf:thinkcmf");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:thinkcmf:thinkcmf:*:*:*:*:*:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("thinkcmf");
                    assertThat(vs.getProduct()).isEqualTo("thinkcmf");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("*");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isEqualTo("0");
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isNull();
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isNull();
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isNull();
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isNull();
                },
                // Exact-version constraints (vers:generic/0, vers:generic/1, and the 6.0.1
                // exact part of vers:generic/>5|<6|6.0.1) collapse into a single CPE entry,
                // because the CPE's version is always taken from the CPE itself ("*" here).
                //
                // Note that the constellations in this test are fabricated and do not represent
                // real-world data. It thus merely documents behaviour.
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/a:thinkcmf:thinkcmf");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:thinkcmf:thinkcmf:*:*:*:*:*:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("thinkcmf");
                    assertThat(vs.getProduct()).isEqualTo("thinkcmf");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("*");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isNull();
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isNull();
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isNull();
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isNull();
                },
                // vers:generic/>2
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/a:thinkcmf:thinkcmf");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:thinkcmf:thinkcmf:*:*:*:*:*:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("thinkcmf");
                    assertThat(vs.getProduct()).isEqualTo("thinkcmf");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("*");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isEqualTo("2");
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isNull();
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isNull();
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isNull();
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isNull();
                },
                // vers:generic/>3|<4
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/a:thinkcmf:thinkcmf");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:thinkcmf:thinkcmf:*:*:*:*:*:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("thinkcmf");
                    assertThat(vs.getProduct()).isEqualTo("thinkcmf");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("*");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isEqualTo("3");
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("4");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isNull();
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isNull();
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isNull();
                },
                // Range part of vers:generic/>5|<6|6.0.1.
                // The exact "6.0.1" part collapses into the shared exact-version CPE entry above.
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/a:thinkcmf:thinkcmf");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:thinkcmf:thinkcmf:*:*:*:*:*:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("thinkcmf");
                    assertThat(vs.getProduct()).isEqualTo("thinkcmf");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("*");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isEqualTo("5");
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("6");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isNull();
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isNull();
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isNull();
                },
                // vers:generic/>*|<7
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/a:thinkcmf:thinkcmf");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:thinkcmf:thinkcmf:*:*:*:*:*:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("thinkcmf");
                    assertThat(vs.getProduct()).isEqualTo("thinkcmf");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("*");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isEqualTo("*");
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("7");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isNull();
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isNull();
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isNull();
                },
                // vers:generic/>8
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/a:thinkcmf:thinkcmf");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:thinkcmf:thinkcmf:*:*:*:*:*:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("thinkcmf");
                    assertThat(vs.getProduct()).isEqualTo("thinkcmf");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("*");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isEqualTo("8");
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isNull();
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isNull();
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isNull();
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isNull();
                },
                // vers:generic/<13
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/a:thinkcmf:thinkcmf");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:thinkcmf:thinkcmf:*:*:*:*:*:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("thinkcmf");
                    assertThat(vs.getProduct()).isEqualTo("thinkcmf");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("*");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("13");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isNull();
                    assertThat(vs.getPurlNamespace()).isNull();
                    assertThat(vs.getPurlName()).isNull();
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isNull();
                },
                // purl with vers:generic/*
                vs -> {
                    assertThat(vs.getCpe22()).isNull();
                    assertThat(vs.getCpe23()).isNull();
                    assertThat(vs.getPart()).isNull();
                    assertThat(vs.getVendor()).isNull();
                    assertThat(vs.getProduct()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getUpdate()).isNull();
                    assertThat(vs.getEdition()).isNull();
                    assertThat(vs.getLanguage()).isNull();
                    assertThat(vs.getSwEdition()).isNull();
                    assertThat(vs.getTargetSw()).isNull();
                    assertThat(vs.getTargetHw()).isNull();
                    assertThat(vs.getOther()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isNull();
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(vs.getPurlType()).isEqualTo("maven");
                    assertThat(vs.getPurlNamespace()).isEqualTo("com.example");
                    assertThat(vs.getPurlName()).isEqualTo("foo");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getPurlQualifiers()).isNull();
                    assertThat(vs.getPurlSubpath()).isNull();
                    assertThat(vs.getPurl()).isEqualTo("pkg:maven/com.example/foo");
                }
        );
    }

    @Test
    void shouldProcessVulnWithInvalidCpeOrPurl() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "02cd44fb-2f0a-569b-a508-1e179e123e38",
                      "cpe": "invalid"
                    },
                    {
                      "bomRef": "3c41e06b-5923-5392-a1e3-64a630c97591",
                      "purl": "invalid"
                    },
                    {
                      "bomRef": "e5dc290a-c649-5f73-b814-c9a47690a48a",
                      "cpe": null,
                      "purl": null
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "CVE-2022-40489",
                      "source": { "name": "NVD" },
                      "affects": [
                        {
                          "ref": "02cd44fb-2f0a-569b-a508-1e179e123e38",
                          "versions": [
                            { "version": "6.0.7" }
                          ]
                        },
                        {
                          "ref": "02cd44fb-2f0a-569b-a508-1e179e123e38",
                          "versions": [
                            { "range": "vers:generic/<=6.0.7" }
                          ]
                        },
                        {
                          "ref": "3c41e06b-5923-5392-a1e3-64a630c97591",
                          "versions": [
                            { "version": "6.0.7" }
                          ]
                        },
                        {
                          "ref": "3c41e06b-5923-5392-a1e3-64a630c97591",
                          "versions": [
                            { "range": "vers:generic/<=6.0.7" }
                          ]
                        },
                        {
                          "ref": "e5dc290a-c649-5f73-b814-c9a47690a48a",
                          "versions": [
                            { "version": "6.0.7" }
                          ]
                        },
                        {
                          "ref": "e5dc290a-c649-5f73-b814-c9a47690a48a",
                          "versions": [
                            { "range": "vers:generic/<=6.0.7" }
                          ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        final var activity = new MirrorVulnDataSourceActivity(createPluginManager("nvd", dataSourceMock));
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder().setDataSourceName("nvd").setSourceName("NVD").build());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("NVD", "CVE-2022-40489");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("CVE-2022-40489");
        assertThat(vuln.getFriendlyVulnId()).isNull();
        assertThat(vuln.getSource()).isEqualTo("NVD");
        assertThat(vuln.getTitle()).isNull();
        assertThat(vuln.getSubTitle()).isNull();
        assertThat(vuln.getDescription()).isNull();
        assertThat(vuln.getDetail()).isNull();
        assertThat(vuln.getRecommendation()).isNull();
        assertThat(vuln.getCwes()).isNull();
        assertThat(vuln.getCreated()).isNull();
        assertThat(vuln.getPublished()).isNull();
        assertThat(vuln.getUpdated()).isNull();
        assertThat(vuln.getCvssV2Vector()).isNull();
        assertThat(vuln.getCvssV2BaseScore()).isNull();
        assertThat(vuln.getCvssV2ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3Vector()).isNull();
        assertThat(vuln.getCvssV3BaseScore()).isNull();
        assertThat(vuln.getCvssV3ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNull();
        assertThat(vuln.getOwaspRRVector()).isNull();
        assertThat(vuln.getOwaspRRLikelihoodScore()).isNull();
        assertThat(vuln.getOwaspRRBusinessImpactScore()).isNull();
        assertThat(vuln.getOwaspRRTechnicalImpactScore()).isNull();
        assertThat(vuln.getSeverity()).isEqualTo(Severity.UNASSIGNED);
        assertThat(vuln.getReferences()).isNull();
        assertThat(vuln.getCredits()).isNull();
        assertThat(vuln.getVulnerableVersions()).isNull();
        assertThat(vuln.getPatchedVersions()).isNull();
        assertThat(vuln.getVulnerableSoftware()).isEmpty();
    }

    @Test
    void shouldNotChurnAffectedVersionAttributionWhenReMirroringIdenticalData() throws Exception {
        final var bovJson = /* language=JSON */ """
                {
                  "components": [
                    {
                      "bomRef": "component",
                      "purl": "pkg:maven/com.acme/product@1.0.0"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "CVE-2024-0001",
                      "source": { "name": "NVD" },
                      "affects": [
                        {
                          "ref": "component",
                          "versions": [
                            { "range": "vers:maven/>=0" }
                          ]
                        }
                      ]
                    }
                  ]
                }
                """;
        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        final var activity = new MirrorVulnDataSourceActivity(createPluginManager("nvd", dataSourceMock));
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder().setDataSourceName("nvd").setSourceName("NVD").build());

        Vulnerability vuln = qm.getVulnerabilityByVulnId("NVD", "CVE-2024-0001");
        List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(vuln, vuln.getVulnerableSoftware());
        assertThat(attributions).hasSize(1);
        final long attributionId = attributions.getFirst().getId();

        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder().setDataSourceName("nvd").setSourceName("NVD").build());

        vuln = qm.getVulnerabilityByVulnId("NVD", "CVE-2024-0001");
        attributions = qm.getAffectedVersionAttributions(vuln, vuln.getVulnerableSoftware());
        assertThat(attributions).satisfiesExactly(
                attribution -> assertThat(attribution.getId()).isEqualTo(attributionId));
    }

    @Test
    void shouldNotChurnAffectedVersionAttributionWhenPurlVersionIsDropped() throws Exception {
        final var bovJson = /* language=JSON */ """
                {
                  "components": [
                    {
                      "bomRef": "component",
                      "purl": "pkg:deb/ubuntu/product@1.0.0?distro=jammy"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "CVE-2024-0001",
                      "source": { "name": "NVD" },
                      "affects": [
                        {
                          "ref": "component",
                          "versions": [
                            { "range": "vers:deb/>=0" }
                          ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(generateBomFromJson(bovJson)).when(dataSourceMock).next();

        var activity = new MirrorVulnDataSourceActivity(createPluginManager("nvd", dataSourceMock));
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder().setDataSourceName("nvd").setSourceName("NVD").build());

        Vulnerability vuln = qm.getVulnerabilityByVulnId("NVD", "CVE-2024-0001");
        List<AffectedVersionAttribution> attributions =
                qm.getAffectedVersionAttributions(vuln, vuln.getVulnerableSoftware());
        assertThat(attributions).hasSize(1);
        final long attributionId = attributions.getFirst().getId();

        final var bovJsonVersionLess = bovJson.replace("product@1.0.0", "product");
        pluginManager.close();
        final var dataSourceMockVersionLess = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMockVersionLess).hasNext();
        doReturn(generateBomFromJson(bovJsonVersionLess)).when(dataSourceMockVersionLess).next();

        activity = new MirrorVulnDataSourceActivity(createPluginManager("nvd", dataSourceMockVersionLess));
        activity.execute(mock(ActivityContext.class), MirrorVulnDataSourceArg.newBuilder().setDataSourceName("nvd").setSourceName("NVD").build());

        vuln = qm.getVulnerabilityByVulnId("NVD", "CVE-2024-0001");
        attributions = qm.getAffectedVersionAttributions(vuln, vuln.getVulnerableSoftware());
        assertThat(attributions).hasSize(1);
        assertThat(attributions.getFirst().getId()).isEqualTo(attributionId);
    }

    private static class TestVulnDataSourceFactory implements VulnDataSourceFactory {

        private final String name;
        private final Supplier<VulnDataSource> dataSourceSupplier;

        private TestVulnDataSourceFactory(String name, Supplier<VulnDataSource> dataSourceSupplier) {
            this.name = name;
            this.dataSourceSupplier = dataSourceSupplier;
        }

        @Override
        public boolean isDataSourceEnabled() {
            return true;
        }

        @Override
        public String extensionName() {
            return name;
        }

        @Override
        public Class<? extends VulnDataSource> extensionClass() {
            return TestVulnDataSource.class;
        }

        @Override
        public int priority() {
            return 0;
        }

        @Override
        public void init(ServiceRegistry serviceRegistry) {
        }

        @Override
        public VulnDataSource create() {
            return dataSourceSupplier.get();
        }

    }

    private static class TestVulnDataSource implements VulnDataSource {

        @Override
        public boolean hasNext() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Bom next() {
            throw new UnsupportedOperationException();
        }

    }

    private static class DisabledVulnDataSourceFactory implements VulnDataSourceFactory {

        private final String name;

        private DisabledVulnDataSourceFactory(String name) {
            this.name = name;
        }

        @Override
        public boolean isDataSourceEnabled() {
            return false;
        }

        @Override
        public String extensionName() {
            return name;
        }

        @Override
        public Class<? extends VulnDataSource> extensionClass() {
            return TestVulnDataSource.class;
        }

        @Override
        public int priority() {
            return 0;
        }

        @Override
        public void init(ServiceRegistry serviceRegistry) {
        }

        @Override
        public VulnDataSource create() {
            throw new UnsupportedOperationException();
        }

    }

}