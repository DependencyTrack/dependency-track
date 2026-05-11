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
package org.dependencytrack.policy.cel.persistence;

import alpine.model.IConfigProperty.PropertyType;
import com.github.packageurl.PackageURL;
import com.google.protobuf.Descriptors;
import com.google.protobuf.util.JsonFormat;
import dev.cel.common.types.CelType;
import net.javacrumbs.jsonunit.core.Option;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Epss;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.PackageArtifactMetadata;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.persistence.jdbi.PackageArtifactMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityAliasDao;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_LICENSE;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_LICENSE_GROUP;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_PROJECT_METADATA;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_PROJECT_PROPERTY;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_VULNERABILITY;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_VULNERABILITY_ALIAS;
import static org.hamcrest.Matchers.equalTo;

public class CelPolicyDaoTest extends PersistenceCapableTest {

    @Test
    public void testLoadRequiredFieldsForProject() throws Exception {
        final var project = new Project();
        project.setGroup("projectGroup");
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setClassifier(Classifier.APPLICATION);
        project.setCpe("projectCpe");
        project.setPurl("projectPurl");
        project.setSwidTagId("projectSwidTagId");
        project.setLastBomImport(new Date());
        qm.persist(project);

        qm.createProjectProperty(project, "propertyGroup", "propertyName", "propertyValue", PropertyType.STRING, null);

        qm.bind(project, List.of(
                qm.createTag("projectTagA"),
                qm.createTag("projectTagB")
        ));

        var bom = new Bom();
        bom.setProject(project);
        bom.setGenerated(new Date());
        bom.setImported(new Date());
        qm.persist(bom);

        final var requirements = new HashSetValuedHashMap<CelType, String>();
        requirements.putAll(TYPE_PROJECT, org.dependencytrack.proto.policy.v1.Project.getDescriptor().getFields().stream()
                .map(Descriptors.FieldDescriptor::getName)
                .toList());
        requirements.putAll(TYPE_PROJECT_PROPERTY, org.dependencytrack.proto.policy.v1.Project.Property.getDescriptor().getFields().stream()
                .map(Descriptors.FieldDescriptor::getName)
                .toList());
        requirements.put(TYPE_PROJECT_METADATA, "bom_generated");

        final org.dependencytrack.proto.policy.v1.Project enrichedProject = withJdbiHandle(handle ->
                new CelPolicyDao(handle).loadRequiredFields(project.getId(), requirements));

        assertThatJson(JsonFormat.printer().print(enrichedProject))
                .withMatcher("uuid", equalTo(project.getUuid().toString()))
                .isEqualTo("""
                        {
                          "uuid": "${json-unit.matches:uuid}",
                          "group": "projectGroup",
                          "name": "projectName",
                          "version": "projectVersion",
                          "classifier": "APPLICATION",
                          "isActive": true,
                          "tags": [
                            "projecttaga",
                            "projecttagb"
                          ],
                          "properties": [
                            {
                              "group": "propertyGroup",
                              "name": "propertyName",
                              "value": "propertyValue",
                              "type": "STRING"
                            }
                          ],
                          "cpe": "projectCpe",
                          "purl": "projectPurl",
                          "swidTagId": "projectSwidTagId",
                          "lastBomImport": "${json-unit.any-string}",
                          "metadata": {
                            "bomGenerated": "${json-unit.any-string}"
                          }
                        }
                        """);
    }

    @Test
    public void testLoadRequiredFieldsForComponent() throws Exception {
        final var project = new Project();
        project.setName("projectName");
        qm.persist(project);

        final var licenseGroup = new LicenseGroup();
        licenseGroup.setName("licenseGroupName");
        qm.persist(licenseGroup);

        final var license = new License();
        license.setLicenseId("resolvedLicenseId");
        license.setName("resolvedLicenseName");
        license.setOsiApproved(true);
        license.setFsfLibre(true);
        license.setDeprecatedLicenseId(true);
        license.setCustomLicense(true);
        license.setLicenseGroups(List.of(licenseGroup));
        qm.persist(license);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("componentGroup");
        component.setName("componentName");
        component.setVersion("componentVersion");
        component.setClassifier(Classifier.LIBRARY);
        component.setCpe("componentCpe");
        component.setPurl("pkg:maven/componentGroup/componentName@componentVersion");
        component.setSwidTagId("componentSwidTagId");
        component.setInternal(true);
        component.setMd5("componentMd5");
        component.setSha1("componentSha1");
        component.setSha256("componentSha256");
        component.setSha384("componentSha384");
        component.setSha512("componentSha512");
        component.setSha3_256("componentSha3_256");
        component.setSha3_384("componentSha3_384");
        component.setSha3_512("componentSha3_512");
        component.setBlake2b_256("componentBlake2b_256");
        component.setBlake2b_384("componentBlake2b_384");
        component.setBlake2b_512("componentBlake2b_512");
        component.setBlake3("componentBlake3");
        component.setLicense("componentLicenseName");
        component.setLicenseExpression("componentLicenseExpression");
        component.setResolvedLicense(license);
        qm.persist(component);

        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(
                        new PackageURL("pkg:maven/componentGroup/componentName"),
                        "1.0.0",
                        null,
                        Instant.now(),
                        null,
                        null))));

        useJdbiHandle(handle -> new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                new PackageArtifactMetadata(
                        new PackageURL("pkg:maven/componentGroup/componentName@componentVersion"),
                        new PackageURL("pkg:maven/componentGroup/componentName"),
                        null,
                        null,
                        null,
                        null,
                        new java.util.Date(222).toInstant(),
                        null,
                        null,
                        Instant.now()))));


        final var requirements = new HashSetValuedHashMap<CelType, String>();
        requirements.putAll(TYPE_COMPONENT, org.dependencytrack.proto.policy.v1.Component.getDescriptor().getFields().stream()
                .map(Descriptors.FieldDescriptor::getName)
                .toList());
        requirements.putAll(TYPE_LICENSE, org.dependencytrack.proto.policy.v1.License.getDescriptor().getFields().stream()
                .map(Descriptors.FieldDescriptor::getName)
                .toList());
        requirements.putAll(TYPE_LICENSE_GROUP, org.dependencytrack.proto.policy.v1.License.Group.getDescriptor().getFields().stream()
                .map(Descriptors.FieldDescriptor::getName)
                .toList());

        final org.dependencytrack.proto.policy.v1.Component enrichedComponent = withJdbiHandle(handle ->
                new CelPolicyDao(handle).loadRequiredComponentFields(List.of(component.getId()), requirements))
                .get(component.getId());

        assertThatJson(JsonFormat.printer().print(enrichedComponent))
                .withMatcher("uuid", equalTo(component.getUuid().toString()))
                .isEqualTo("""
                        {
                          "uuid": "${json-unit.matches:uuid}",
                          "group": "componentGroup",
                          "name": "componentName",
                          "version": "componentVersion",
                          "classifier": "LIBRARY",
                          "cpe": "componentCpe",
                          "purl": "pkg:maven/componentGroup/componentName@componentVersion",
                          "swidTagId": "componentSwidTagId",
                          "isInternal": true,
                          "md5": "componentmd5",
                          "sha1": "componentsha1",
                          "sha256": "componentsha256",
                          "sha384": "componentsha384",
                          "sha512": "componentsha512",
                          "sha3256": "componentsha3_256",
                          "sha3384": "componentsha3_384",
                          "sha3512": "componentsha3_512",
                          "blake2b256": "componentBlake2b_256",
                          "blake2b384": "componentBlake2b_384",
                          "blake2b512": "componentBlake2b_512",
                          "blake3": "componentBlake3",
                          "licenseName": "componentLicenseName",
                          "licenseExpression": "componentLicenseExpression",
                          "latestVersion": "1.0.0",
                          "publishedAt": "1970-01-01T00:00:00.222Z"
                        }
                        """);
    }

    @Test
    public void testLoadRequiredFieldsForVulnerability() throws Exception {
        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setCwes(List.of(666, 777));
        vuln.setCreated(new java.util.Date(666));
        vuln.setPublished(new java.util.Date(777));
        vuln.setUpdated(new java.util.Date(888));
        vuln.setSeverity(Severity.INFO);
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(6.0));
        vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(6.4));
        vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(6.8));
        vuln.setCvssV2Vector("(AV:N/AC:M/Au:S/C:P/I:P/A:P)");
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(9.1));
        vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(5.3));
        vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(3.1));
        vuln.setCvssV3Vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.5));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.0));
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.75));
        vuln.setOwaspRRVector("(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)");
        qm.persist(vuln);

        useJdbiTransaction(handle -> new VulnerabilityAliasDao(handle)
                .syncAssertions(
                        "TEST",
                        new VulnerabilityKey("CVE-001", Vulnerability.Source.NVD),
                        Set.of(new VulnerabilityKey("GHSA-001", Vulnerability.Source.GITHUB))));

        final var epss = new Epss();
        epss.setCve("CVE-001");
        epss.setScore(BigDecimal.valueOf(0.6));
        epss.setPercentile(BigDecimal.valueOf(0.2));
        qm.persist(epss);

        final var requirements = new HashSetValuedHashMap<CelType, String>();
        requirements.putAll(TYPE_VULNERABILITY, org.dependencytrack.proto.policy.v1.Vulnerability.getDescriptor().getFields().stream()
                .map(Descriptors.FieldDescriptor::getName)
                .toList());
        requirements.putAll(TYPE_VULNERABILITY_ALIAS, org.dependencytrack.proto.policy.v1.Vulnerability.Alias.getDescriptor().getFields().stream()
                .map(Descriptors.FieldDescriptor::getName)
                .toList());

        final org.dependencytrack.proto.policy.v1.Vulnerability enrichedVuln = withJdbiHandle(handle ->
                new CelPolicyDao(handle).loadRequiredVulnerabilityFields(List.of(vuln.getId()), requirements))
                .get(vuln.getId());

        assertThatJson(JsonFormat.printer().print(enrichedVuln))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("uuid", equalTo(vuln.getUuid().toString()))
                .isEqualTo("""
                        {
                          "uuid": "${json-unit.matches:uuid}",
                          "id": "CVE-001",
                          "source": "NVD",
                          "aliases": [
                            {
                              "id": "GHSA-001",
                              "source": "GITHUB"
                            }
                          ],
                          "cwes": [
                            666,
                            777
                          ],
                          "created": "${json-unit.any-string}",
                          "published": "${json-unit.any-string}",
                          "updated": "${json-unit.any-string}",
                          "severity": "INFO",
                          "cvssv2BaseScore": 6.0,
                          "cvssv2ImpactSubscore": 6.4,
                          "cvssv2ExploitabilitySubscore": 6.8,
                          "cvssv2Vector": "(AV:N/AC:M/Au:S/C:P/I:P/A:P)",
                          "cvssv3BaseScore": 9.1,
                          "cvssv3ImpactSubscore": 5.3,
                          "cvssv3ExploitabilitySubscore": 3.1,
                          "cvssv3Vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L",
                          "owaspRrLikelihoodScore": 4.5,
                          "owaspRrTechnicalImpactScore": 5.0,
                          "owaspRrBusinessImpactScore": 3.75,
                          "owaspRrVector": "(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)",
                          "epssScore": 0.6,
                          "epssPercentile": 0.2
                        }
                        """);
    }

}