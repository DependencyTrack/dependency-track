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
package org.dependencytrack.persistence.jdbi;

import com.google.protobuf.util.JsonFormat;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerableDependencySubject;
import org.dependencytrack.notification.proto.v1.PolicyViolationSubject;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.command.MakeViolationAnalysisCommand;
import org.dependencytrack.persistence.jdbi.query.GetProjectAuditChangeNotificationSubjectQuery;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.hamcrest.Matchers.equalTo;

public class NotificationSubjectDaoTest extends PersistenceCapableTest {

    @Test
    public void testGetForNewVulnerabilities() {
        final var project = new Project();
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setDescription("projectDescription");
        project.setPurl("projectPurl");
        qm.persist(project);
        qm.bind(project, List.of(
                qm.createTag("projectTagA"),
                qm.createTag("projectTagB")
        ));

        final var component = new Component();
        component.setProject(project);
        component.setGroup("componentGroup");
        component.setName("componentName");
        component.setVersion("componentVersion");
        component.setPurl("componentPurl");
        component.setMd5("componentMd5");
        component.setSha1("componentSha1");
        component.setSha256("componentSha256");
        component.setSha512("componentSha512");
        qm.persist(component);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("CVE-100");
        vulnA.setSource(Vulnerability.Source.NVD);
        vulnA.setTitle("vulnATitle");
        vulnA.setSubTitle("vulnASubTitle");
        vulnA.setDescription("vulnADescription");
        vulnA.setRecommendation("vulnARecommendation");
        vulnA.setSeverity(Severity.LOW);
        vulnA.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vulnA.setCvssV3BaseScore(BigDecimal.valueOf(2.2));
        vulnA.setCvssV2Vector("(AV:N/AC:M/Au:S/C:P/I:P/A:P)");
        vulnA.setCvssV3Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
        vulnA.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.3));
        vulnA.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.4));
        vulnA.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.5));
        vulnA.setOwaspRRVector("(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)");
        vulnA.setCwes(List.of(666, 777));
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("CVE-200");
        vulnB.setSource(Vulnerability.Source.NVD);
        qm.persist(vulnB);

        useJdbiTransaction(handle -> {
            new VulnerabilityAliasDao(handle)
                    .syncAssertions(
                            "TEST",
                            new VulnerabilityKey("CVE-100", Vulnerability.Source.NVD),
                            Set.of(new VulnerabilityKey("GHSA-100", Vulnerability.Source.GITHUB)));
            handle
                    .attach(KevDao.class)
                    .upsertBatch("cisa", List.of(
                            new KevAssertion(
                                    "NVD",
                                    "CVE-100",
                                    null,
                                    null,
                                    null,
                                    null,
                                    null)));
        });

        qm.addVulnerability(vulnA, component, "internal");
        qm.addVulnerability(vulnB, component, "internal");

        // Suppress vulnB, it should not appear in the query results.
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vulnB)
                        .withState(AnalysisState.FALSE_POSITIVE)
                        .withSuppress(true));

        final List<NewVulnerabilitySubject> subjects = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerabilities(
                        List.of(component.getId(), component.getId()), List.of(vulnA.getId(), vulnB.getId())));

        assertThat(subjects).satisfiesExactly(subject ->
                assertThatJson(JsonFormat.printer().print(subject))
                        .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                        .withMatcher("componentUuid", equalTo(component.getUuid().toString()))
                        .withMatcher("vulnUuid", equalTo(vulnA.getUuid().toString()))
                        .isEqualTo(/* language=JSON */ """
                                {
                                  "affectedProjects": [
                                    {
                                      "description": "projectDescription",
                                      "name": "projectName",
                                      "purl": "projectPurl",
                                      "isActive":true,
                                      "tags": [
                                        "projecttaga",
                                        "projecttagb"
                                      ],
                                      "uuid": "${json-unit.matches:projectUuid}",
                                      "version": "projectVersion"
                                    }
                                  ],
                                  "component": {
                                    "group": "componentGroup",
                                    "md5": "componentmd5",
                                    "name": "componentName",
                                    "purl": "componentPurl",
                                    "sha1": "componentsha1",
                                    "sha256": "componentsha256",
                                    "sha512": "componentsha512",
                                    "uuid": "${json-unit.matches:componentUuid}",
                                    "version": "componentVersion"
                                  },
                                  "project": {
                                    "description": "projectDescription",
                                    "name": "projectName",
                                    "purl": "projectPurl",
                                    "isActive":true,
                                    "tags": [
                                      "projecttaga",
                                      "projecttagb"
                                    ],
                                    "uuid": "${json-unit.matches:projectUuid}",
                                    "version": "projectVersion"
                                  },
                                  "vulnerability": {
                                    "aliases": [
                                      {"vulnId": "GHSA-100", "source": "GITHUB"}
                                    ],
                                    "cvssv2": 1.1,
                                    "cvssv3": 2.2,
                                    "cwes": [
                                      {
                                        "cweId": 666,
                                        "name": "Operation on Resource in Wrong Phase of Lifetime"
                                      },
                                      {
                                        "cweId": 777,
                                        "name": "Regular Expression without Anchors"
                                      }
                                    ],
                                    "description": "vulnADescription",
                                    "owaspRRBusinessImpact": 3.3,
                                    "owaspRRLikelihood": 4.4,
                                    "owaspRRTechnicalImpact": 5.5,
                                    "recommendation": "vulnARecommendation",
                                    "severity": "LOW",
                                    "source": "NVD",
                                    "subtitle": "vulnASubTitle",
                                    "title": "vulnATitle",
                                    "uuid": "${json-unit.matches:vulnUuid}",
                                    "vulnId": "CVE-100",
                                    "cvssV2Vector": "(AV:N/AC:M/Au:S/C:P/I:P/A:P)",
                                    "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                    "owaspRRVector": "(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)",
                                    "isKev": true
                                  }
                                }
                                """));
    }

    @Test
    public void testGetForNewVulnerabilityWithAnalysisRatingOverwrite() throws Exception {
        final var project = new Project();
        project.setName("projectName");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("componentName");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-100");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.MEDIUM);
        vuln.setCvssV2Vector("");
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(1.2));
        vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(1.3));
        vuln.setCvssV3Vector("cvssV3Vector");
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(2.1));
        vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(2.2));
        vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(2.3));
        vuln.setOwaspRRVector("owaspRrVector");
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.1));
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(3.2));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(3.3));
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "internal");

        final var analysis = new Analysis();
        analysis.setComponent(component);
        analysis.setVulnerability(vuln);
        analysis.setAnalysisState(AnalysisState.EXPLOITABLE);
        analysis.setSeverity(Severity.CRITICAL);
        analysis.setCvssV3Vector("cvssV3VectorOverwrite");
        analysis.setCvssV3Score(BigDecimal.valueOf(10.0));
        qm.persist(analysis);

        final List<NewVulnerabilitySubject> subjects = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerabilities(List.of(component.getId()), List.of(vuln.getId())));

        assertThat(subjects).hasSize(1);
        assertThatJson(JsonFormat.printer().print(subjects.getFirst()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentUuid", equalTo(component.getUuid().toString()))
                .withMatcher("vulnUuid", equalTo(vuln.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "component": {
                            "uuid": "${json-unit.matches:componentUuid}",
                            "name": "componentName"
                          },
                          "project": {
                            "uuid": "${json-unit.matches:projectUuid}",
                            "name": "projectName",
                            "isActive":true
                          },
                          "vulnerability": {
                            "uuid": "${json-unit.matches:vulnUuid}",
                            "vulnId": "CVE-100",
                            "source": "NVD",
                            "cvssv2": 1.1,
                            "cvssv3": 10.0,
                            "owaspRRBusinessImpact": 3.1,
                            "owaspRRLikelihood": 3.2,
                            "owaspRRTechnicalImpact": 3.3,
                            "severity": "CRITICAL",
                            "cvssV2Vector": "",
                            "cvssV3Vector": "cvssV3VectorOverwrite",
                            "owaspRRVector": "owaspRrVector",
                            "isKev": false
                          },
                          "affectedProjects": [
                            {
                              "uuid": "${json-unit.matches:projectUuid}",
                              "name": "projectName",
                              "isActive":true
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testGetForNewVulnerableDependency() throws Exception {
        final var project = new Project();
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setDescription("projectDescription");
        project.setPurl("projectPurl");
        qm.persist(project);
        qm.bind(project, List.of(
                qm.createTag("projectTagA"),
                qm.createTag("projectTagB")
        ));

        final var component = new Component();
        component.setProject(project);
        component.setGroup("componentGroup");
        component.setName("componentName");
        component.setVersion("componentVersion");
        component.setPurl("componentPurl");
        component.setMd5("componentMd5");
        component.setSha1("componentSha1");
        component.setSha256("componentSha256");
        component.setSha512("componentSha512");
        qm.persist(component);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("CVE-100");
        vulnA.setSource(Vulnerability.Source.NVD);
        vulnA.setTitle("vulnATitle");
        vulnA.setSubTitle("vulnASubTitle");
        vulnA.setDescription("vulnADescription");
        vulnA.setRecommendation("vulnARecommendation");
        vulnA.setSeverity(Severity.LOW);
        vulnA.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vulnA.setCvssV3BaseScore(BigDecimal.valueOf(2.2));
        vulnA.setCvssV2Vector("(AV:N/AC:M/Au:S/C:P/I:P/A:P)");
        vulnA.setCvssV3Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
        vulnA.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.3));
        vulnA.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.4));
        vulnA.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.5));
        vulnA.setOwaspRRVector("(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)");
        vulnA.setCwes(List.of(666, 777));
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("CVE-200");
        vulnB.setSource(Vulnerability.Source.NVD);
        qm.persist(vulnB);

        useJdbiTransaction(handle -> {
            new VulnerabilityAliasDao(handle)
                    .syncAssertions(
                            "TEST",
                            new VulnerabilityKey("CVE-100", Vulnerability.Source.NVD),
                            Set.of(new VulnerabilityKey("GHSA-100", Vulnerability.Source.GITHUB)));

            handle
                    .attach(KevDao.class)
                    .upsertBatch("cisa", List.of(
                            new KevAssertion(
                                    "NVD",
                                    "CVE-100",
                                    null,
                                    null,
                                    null,
                                    null,
                                    null)));
        });

        qm.addVulnerability(vulnA, component, "internal");
        qm.addVulnerability(vulnB, component, "internal");

        // Suppress vulnB, it should not appear in the query results.
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vulnB)
                        .withState(AnalysisState.FALSE_POSITIVE)
                        .withSuppress(true));

        final List<NewVulnerableDependencySubject> subjects = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerableDependencies(List.of(component.getId())));

        assertThat(subjects).hasSize(1);
        assertThatJson(JsonFormat.printer().print(subjects.getFirst()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentUuid", equalTo(component.getUuid().toString()))
                .withMatcher("vulnUuid", equalTo(vulnA.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "component": {
                            "uuid": "${json-unit.matches:componentUuid}",
                            "group": "componentGroup",
                            "name": "componentName",
                            "version": "componentVersion",
                            "purl": "componentPurl",
                            "md5": "componentmd5",
                            "sha1": "componentsha1",
                            "sha256": "componentsha256",
                            "sha512": "componentsha512"
                          },
                          "project": {
                            "uuid": "${json-unit.matches:projectUuid}",
                            "name": "projectName",
                            "version": "projectVersion",
                            "description": "projectDescription",
                            "purl": "projectPurl",
                            "isActive":true,
                            "tags": [
                              "projecttaga",
                              "projecttagb"
                            ]
                          },
                          "vulnerabilities": [
                            {
                              "uuid": "${json-unit.matches:vulnUuid}",
                              "vulnId": "CVE-100",
                              "source": "NVD",
                              "title": "vulnATitle",
                              "subtitle": "vulnASubTitle",
                              "description": "vulnADescription",
                              "recommendation": "vulnARecommendation",
                              "cvssv2": 1.1,
                              "cvssv3": 2.2,
                              "owaspRRLikelihood": 4.4,
                              "owaspRRTechnicalImpact": 5.5,
                              "owaspRRBusinessImpact": 3.3,
                              "severity": "LOW",
                              "cwes": [
                                {
                                  "cweId": 666,
                                  "name": "Operation on Resource in Wrong Phase of Lifetime"
                                },
                                {
                                  "cweId": 777,
                                  "name": "Regular Expression without Anchors"
                                }
                              ],
                              "cvssV2Vector": "(AV:N/AC:M/Au:S/C:P/I:P/A:P)",
                              "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                              "owaspRRVector": "(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)",
                              "aliases": [
                                {"vulnId": "GHSA-100", "source": "GITHUB"}
                              ],
                              "isKev": true
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testGetForNewVulnerableDependencyWithAnalysisRatingOverwrite() throws Exception {
        final var project = new Project();
        project.setName("projectName");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("componentName");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-100");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.MEDIUM);
        vuln.setCvssV2Vector("");
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(1.2));
        vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(1.3));
        vuln.setCvssV3Vector("cvssV3Vector");
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(2.1));
        vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(2.2));
        vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(2.3));
        vuln.setOwaspRRVector("owaspRrVector");
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.1));
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(3.2));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(3.3));
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "internal");

        final var analysis = new Analysis();
        analysis.setComponent(component);
        analysis.setVulnerability(vuln);
        analysis.setAnalysisState(AnalysisState.EXPLOITABLE);
        analysis.setSeverity(Severity.CRITICAL);
        analysis.setCvssV3Vector("cvssV3VectorOverwrite");
        analysis.setCvssV3Score(BigDecimal.valueOf(10.0));
        qm.persist(analysis);

        final List<NewVulnerableDependencySubject> subjects = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerableDependencies(List.of(component.getId())));

        assertThat(subjects).hasSize(1);
        assertThatJson(JsonFormat.printer().print(subjects.getFirst()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentUuid", equalTo(component.getUuid().toString()))
                .withMatcher("vulnUuid", equalTo(vuln.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "component": {
                            "uuid": "${json-unit.matches:componentUuid}",
                            "name": "componentName"
                          },
                          "project": {
                            "uuid": "${json-unit.matches:projectUuid}",
                            "name": "projectName",
                            "isActive":true
                          },
                          "vulnerabilities": [
                            {
                              "uuid": "${json-unit.matches:vulnUuid}",
                              "vulnId": "CVE-100",
                              "source": "NVD",
                              "cvssv2": 1.1,
                              "cvssv3": 10.0,
                              "owaspRRBusinessImpact": 3.1,
                              "owaspRRLikelihood": 3.2,
                              "owaspRRTechnicalImpact": 3.3,
                              "severity": "CRITICAL",
                              "cvssV2Vector": "",
                              "cvssV3Vector": "cvssV3VectorOverwrite",
                              "owaspRRVector": "owaspRrVector",
                              "isKev": false
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testGetForProjectAuditChange() {
        final var project = new Project();
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setDescription("projectDescription");
        project.setPurl("projectPurl");
        qm.persist(project);
        qm.bind(project, List.of(
                qm.createTag("projectTagA"),
                qm.createTag("projectTagB")
        ));

        final var component = new Component();
        component.setProject(project);
        component.setGroup("componentGroup");
        component.setName("componentName");
        component.setVersion("componentVersion");
        component.setPurl("componentPurl");
        component.setMd5("componentMd5");
        component.setSha1("componentSha1");
        component.setSha256("componentSha256");
        component.setSha512("componentSha512");
        qm.persist(component);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("CVE-100");
        vulnA.setSource(Vulnerability.Source.NVD);
        vulnA.setTitle("vulnATitle");
        vulnA.setSubTitle("vulnASubTitle");
        vulnA.setDescription("vulnADescription");
        vulnA.setRecommendation("vulnARecommendation");
        vulnA.setSeverity(Severity.LOW);
        vulnA.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vulnA.setCvssV3BaseScore(BigDecimal.valueOf(2.2));
        vulnA.setCvssV2Vector("(AV:N/AC:M/Au:S/C:P/I:P/A:P)");
        vulnA.setCvssV3Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
        vulnA.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.3));
        vulnA.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.4));
        vulnA.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.5));
        vulnA.setOwaspRRVector("(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)");
        vulnA.setCwes(List.of(666, 777));
        qm.persist(vulnA);

        useJdbiTransaction(handle -> {
            new VulnerabilityAliasDao(handle)
                    .syncAssertions(
                            "TEST",
                            new VulnerabilityKey("CVE-100", Vulnerability.Source.NVD),
                            Set.of(new VulnerabilityKey("GHSA-100", Vulnerability.Source.GITHUB)));

            handle
                    .attach(KevDao.class)
                    .upsertBatch("cisa", List.of(
                            new KevAssertion(
                                    "NVD",
                                    "CVE-100",
                                    null,
                                    null,
                                    null,
                                    null,
                                    null)));
        });

        qm.addVulnerability(vulnA, component, "internal");

        // Suppress vulnB, it should not appear in the query results.
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vulnA)
                        .withState(AnalysisState.NOT_AFFECTED));

        var policyAnalysis = qm.getAnalysis(component, vulnA);

        final List<VulnerabilityAnalysisDecisionChangeSubject> subjects =
                withJdbiHandle(handle -> handle
                        .attach(NotificationSubjectDao.class)
                        .getForProjectAuditChanges(List.of(
                                new GetProjectAuditChangeNotificationSubjectQuery(
                                        component.getId(), vulnA.getId(), policyAnalysis.getAnalysisState(), policyAnalysis.isSuppressed()))));

        assertThat(subjects).satisfiesExactly(subject ->
                assertThatJson(JsonFormat.printer().print(subject))
                        .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                        .withMatcher("componentUuid", equalTo(component.getUuid().toString()))
                        .withMatcher("vulnUuid", equalTo(vulnA.getUuid().toString()))
                        .isEqualTo(/* language=JSON */ """
                                {
                                     "component": {
                                         "uuid": "${json-unit.matches:componentUuid}",
                                         "group": "componentGroup",
                                         "name": "componentName",
                                         "version": "componentVersion",
                                         "purl": "componentPurl",
                                         "md5": "componentmd5",
                                         "sha1": "componentsha1",
                                         "sha256": "componentsha256",
                                         "sha512": "componentsha512"
                                     },
                                     "project": {
                                         "uuid": "${json-unit.matches:projectUuid}",
                                         "name": "projectName",
                                         "version": "projectVersion",
                                         "description": "projectDescription",
                                         "isActive":true,
                                         "purl": "projectPurl",
                                         "tags": [
                                             "projecttaga",
                                             "projecttagb"
                                         ]
                                     },
                                     "vulnerability": {
                                         "uuid": "${json-unit.matches:vulnUuid}",
                                         "vulnId": "CVE-100",
                                         "source": "NVD",
                                         "aliases": [
                                             {
                                                 "vulnId": "GHSA-100",
                                                 "source": "GITHUB"
                                             }
                                         ],
                                         "title": "vulnATitle",
                                         "subtitle": "vulnASubTitle",
                                         "description": "vulnADescription",
                                         "recommendation": "vulnARecommendation",
                                         "cvssv2": 1.1,
                                         "cvssv3": 2.2,
                                         "owaspRRLikelihood": 4.4,
                                         "owaspRRTechnicalImpact": 5.5,
                                         "owaspRRBusinessImpact": 3.3,
                                         "severity": "LOW",
                                         "cwes": [
                                             {
                                                 "cweId": 666,
                                                 "name": "Operation on Resource in Wrong Phase of Lifetime"
                                             },
                                             {
                                                 "cweId": 777,
                                                 "name": "Regular Expression without Anchors"
                                             }
                                         ],
                                         "cvssV2Vector": "(AV:N/AC:M/Au:S/C:P/I:P/A:P)",
                                         "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                         "owaspRRVector": "(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)",
                                         "isKev": true
                                     },
                                     "analysis": {
                                         "component": {
                                             "uuid": "${json-unit.matches:componentUuid}",
                                             "group": "componentGroup",
                                             "name": "componentName",
                                             "version": "componentVersion",
                                             "purl": "componentPurl",
                                             "md5": "componentmd5",
                                             "sha1": "componentsha1",
                                             "sha256": "componentsha256",
                                             "sha512": "componentsha512"
                                         },
                                         "project": {
                                             "uuid": "${json-unit.matches:projectUuid}",
                                             "name": "projectName",
                                             "version": "projectVersion",
                                             "description": "projectDescription",
                                             "purl": "projectPurl",
                                             "isActive":true,
                                             "tags": [
                                                 "projecttaga",
                                                 "projecttagb"
                                             ]
                                         },
                                         "vulnerability": {
                                             "uuid": "${json-unit.matches:vulnUuid}",
                                             "vulnId": "CVE-100",
                                             "source": "NVD",
                                             "aliases": [
                                                 {
                                                     "vulnId": "GHSA-100",
                                                     "source": "GITHUB"
                                                 }
                                             ],
                                             "title": "vulnATitle",
                                             "subtitle": "vulnASubTitle",
                                             "description": "vulnADescription",
                                             "recommendation": "vulnARecommendation",
                                             "cvssv2": 1.1,
                                             "cvssv3": 2.2,
                                             "owaspRRLikelihood": 4.4,
                                             "owaspRRTechnicalImpact": 5.5,
                                             "owaspRRBusinessImpact": 3.3,
                                             "severity": "LOW",
                                             "cwes": [
                                                 {
                                                     "cweId": 666,
                                                     "name": "Operation on Resource in Wrong Phase of Lifetime"
                                                 },
                                                 {
                                                     "cweId": 777,
                                                     "name": "Regular Expression without Anchors"
                                                 }
                                             ],
                                         "cvssV2Vector": "(AV:N/AC:M/Au:S/C:P/I:P/A:P)",
                                         "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                         "owaspRRVector": "(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)",
                                         "isKev": true
                                         },
                                         "state": "NOT_AFFECTED",
                                         "suppressed": false
                                     }
                                 }
                                """));
    }

    @Test
    public void shouldGetForNewPolicyViolations() {
        final var project = new Project();
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setDescription("projectDescription");
        project.setPurl("projectPurl");
        qm.persist(project);
        qm.bind(project, List.of(
                qm.createTag("projectTagA"),
                qm.createTag("projectTagB")
        ));

        final var component = new Component();
        component.setProject(project);
        component.setGroup("componentGroup");
        component.setName("componentName");
        component.setVersion("componentVersion");
        component.setPurl("componentPurl");
        component.setMd5("componentMd5");
        component.setSha1("componentSha1");
        component.setSha256("componentSha256");
        component.setSha512("componentSha512");
        qm.persist(component);

        final var policy = qm.createPolicy("testPolicy", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final var condition = qm.createPolicyCondition(policy, Subject.VERSION, Operator.NUMERIC_EQUAL, "1.0");

        final var violation = new PolicyViolation();
        violation.setType(PolicyViolation.Type.OPERATIONAL);
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setTimestamp(new Date());
        qm.persist(violation);

        final List<PolicyViolationSubject> subjects = withJdbiHandle(handle -> handle
                .attach(NotificationSubjectDao.class)
                .getForNewPolicyViolations(List.of(violation.getId())));

        assertThat(subjects).satisfiesExactly(subject ->
                assertThatJson(JsonFormat.printer().print(subject))
                        .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                        .withMatcher("componentUuid", equalTo(component.getUuid().toString()))
                        .withMatcher("violationUuid", equalTo(violation.getUuid().toString()))
                        .withMatcher("conditionUuid", equalTo(condition.getUuid().toString()))
                        .withMatcher("policyUuid", equalTo(policy.getUuid().toString()))
                        .isEqualTo(/* language=JSON */ """
                                {
                                  "project": {
                                    "uuid": "${json-unit.matches:projectUuid}",
                                    "name": "projectName",
                                    "version": "projectVersion",
                                    "description": "projectDescription",
                                    "purl": "projectPurl",
                                    "isActive": true,
                                    "tags": [
                                      "projecttaga",
                                      "projecttagb"
                                    ]
                                  },
                                  "component": {
                                    "uuid": "${json-unit.matches:componentUuid}",
                                    "group": "componentGroup",
                                    "name": "componentName",
                                    "version": "componentVersion",
                                    "purl": "componentPurl",
                                    "md5": "componentmd5",
                                    "sha1": "componentsha1",
                                    "sha256": "componentsha256",
                                    "sha512": "componentsha512"
                                  },
                                  "policyViolation": {
                                    "uuid": "${json-unit.matches:violationUuid}",
                                    "type": "OPERATIONAL",
                                    "timestamp": "${json-unit.any-string}",
                                    "condition": {
                                      "uuid": "${json-unit.matches:conditionUuid}",
                                      "subject": "VERSION",
                                      "operator": "NUMERIC_EQUAL",
                                      "value": "1.0",
                                      "policy": {
                                        "uuid": "${json-unit.matches:policyUuid}",
                                        "name": "testPolicy",
                                        "violationState": "FAIL"
                                      }
                                    }
                                  }
                                }
                                """));
    }

    @Test
    public void shouldFilterSuppressedViolationsForNewPolicyViolations() {
        final var project = new Project();
        project.setName("projectName");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("componentName");
        qm.persist(component);

        final var policy = qm.createPolicy("testPolicy", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final var conditionA = qm.createPolicyCondition(policy, Subject.VERSION, Operator.NUMERIC_EQUAL, "1.0");
        final var conditionB = qm.createPolicyCondition(policy, Subject.VERSION, Operator.NUMERIC_EQUAL, "2.0");

        final var violationA = new PolicyViolation();
        violationA.setType(PolicyViolation.Type.OPERATIONAL);
        violationA.setComponent(component);
        violationA.setPolicyCondition(conditionA);
        violationA.setTimestamp(new Date());
        qm.persist(violationA);

        final var violationB = new PolicyViolation();
        violationB.setType(PolicyViolation.Type.OPERATIONAL);
        violationB.setComponent(component);
        violationB.setPolicyCondition(conditionB);
        violationB.setTimestamp(new Date());
        qm.persist(violationB);

        qm.makeViolationAnalysis(
                new MakeViolationAnalysisCommand(component, violationB)
                        .withState(ViolationAnalysisState.REJECTED)
                        .withSuppress(true));

        final List<PolicyViolationSubject> subjects = withJdbiHandle(handle -> handle
                .attach(NotificationSubjectDao.class)
                .getForNewPolicyViolations(List.of(violationA.getId(), violationB.getId())));

        assertThat(subjects).singleElement()
                .extracting(s -> s.getPolicyViolation().getUuid())
                .isEqualTo(violationA.getUuid().toString());
    }

    @Test
    public void shouldFilterApprovedViolationsForNewPolicyViolations() {
        final var project = new Project();
        project.setName("projectName");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("componentName");
        qm.persist(component);

        final var policy = qm.createPolicy("testPolicy", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final var conditionA = qm.createPolicyCondition(policy, Subject.VERSION, Operator.NUMERIC_EQUAL, "1.0");
        final var conditionB = qm.createPolicyCondition(policy, Subject.VERSION, Operator.NUMERIC_EQUAL, "2.0");

        final var violationA = new PolicyViolation();
        violationA.setType(PolicyViolation.Type.OPERATIONAL);
        violationA.setComponent(component);
        violationA.setPolicyCondition(conditionA);
        violationA.setTimestamp(new Date());
        qm.persist(violationA);

        final var violationB = new PolicyViolation();
        violationB.setType(PolicyViolation.Type.OPERATIONAL);
        violationB.setComponent(component);
        violationB.setPolicyCondition(conditionB);
        violationB.setTimestamp(new Date());
        qm.persist(violationB);

        qm.makeViolationAnalysis(
                new MakeViolationAnalysisCommand(component, violationB)
                        .withState(ViolationAnalysisState.APPROVED));

        final List<PolicyViolationSubject> subjects = withJdbiHandle(handle -> handle
                .attach(NotificationSubjectDao.class)
                .getForNewPolicyViolations(List.of(violationA.getId(), violationB.getId())));

        assertThat(subjects).singleElement()
                .extracting(s -> s.getPolicyViolation().getUuid())
                .isEqualTo(violationA.getUuid().toString());
    }

    @Test
    public void shouldReturnEmptyForNewPolicyViolationsWithEmptyInput() {
        final List<PolicyViolationSubject> subjects = withJdbiHandle(handle -> handle
                .attach(NotificationSubjectDao.class)
                .getForNewPolicyViolations(List.of()));

        assertThat(subjects).isEmpty();
    }
}