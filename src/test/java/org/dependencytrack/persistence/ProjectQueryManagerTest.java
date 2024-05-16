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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.*;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Assert;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.*;
import java.util.function.Consumer;


public class ProjectQueryManagerTest extends PersistenceCapableTest {

    Project project;

    private VulnerabilityAlias createAlias(final Consumer<VulnerabilityAlias> customizer) {
        final var alias = new VulnerabilityAlias();
        customizer.accept(alias);
        return alias;
    }

    VulnerabilityAlias alias = createAlias(alias -> {
        alias.setId(1);
        alias.setCveId("CVE-1234-123");
        alias.setGhsaId("GHSA-002");
    });

    private void createConfig(ConfigPropertyConstants constantFlag, String value){
        qm.createConfigProperty(constantFlag.getGroupName(),
        constantFlag.getPropertyName(),
        value,
        constantFlag.getPropertyType(),
        constantFlag.getDescription());
    }

    private Component setUp() {
        List<VulnerabilityAlias> vulnerabilityAliases = new ArrayList<>();
        Component component = new Component();
        Vulnerability vuln = new Vulnerability();
        Vulnerability vuln2 = new Vulnerability();

        vulnerabilityAliases.add(alias);

        project = qm.createProject("Example Project 1", "Description 1", "1.0", null, null, null, true, false);

        component.setId(111L);
        component.setName("name");
        component.setProject(project);
        component.setVersion("1.0");
        component.setCopyright("Copyright Acme");
        qm.createComponent(component, true);

        vuln.setId(124L);
        vuln.setVulnId("CVE-1234-123");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.HIGH);
        vuln.setAliases(vulnerabilityAliases);

        vuln2.setId(125L);
        vuln2.setVulnId("GHSA-002");
        vuln2.setSource(Vulnerability.Source.GITHUB);
        vuln2.setSeverity(Severity.HIGH);
        vuln2.setAliases(vulnerabilityAliases);

        qm.persist(vuln);
        qm.persist(vuln2);

        List <Vulnerability> vulnerabilities = new ArrayList<>();
        vulnerabilities.add(vuln);
        vulnerabilities.add(vuln2);

        for (Vulnerability vulnerability : vulnerabilities){
            qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER, "Vuln", "http://vuln.com/vuln", new Date(1708559165229L));
        }

        List<VulnerabilityAlias> aliases2 = vuln2.getAliases();
        //Confirm Alias
        Assert.assertTrue(aliases2.stream().anyMatch(alias -> "CVE-1234-123".equals(alias.getCveId())));
        List<VulnerabilityAlias> aliases = vuln.getAliases();
        //Confirm Alias
        Assert.assertTrue(aliases.stream().anyMatch(alias -> "GHSA-002".equals(alias.getGhsaId())));

        return component;
    }


    @Test
    public void testCloneProjectPreservesVulnerabilityAttributionDate() throws Exception {
        Project project = qm.createProject("Example Project 1", "Description 1", "1.0", null, null, null, true, false);
        Component comp = new Component();
        comp.setId(111L);
        comp.setName("name");
        comp.setProject(project);
        comp.setVersion("1.0");
        comp.setCopyright("Copyright Acme");
        qm.createComponent(comp, true);
        Vulnerability vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        qm.persist(vuln);
        qm.addVulnerability(vuln, comp, AnalyzerIdentity.INTERNAL_ANALYZER, "Vuln1", "http://vuln.com/vuln1", new Date(1708559165229L));
        Project clonedProject = qm.clone(project.getUuid(), "1.1.0", false, false, true, false, false, false, false);
        List<Finding> findings = qm.getFindings(clonedProject);
        Assert.assertEquals(1, findings.size());
        Finding finding = findings.get(0);
        Assert.assertNotNull(finding);
        Assert.assertFalse(finding.getAttribution().isEmpty());
        Assert.assertEquals(new Date(1708559165229L),finding.getAttribution().get("attributedOn"));
    }

    /*
     * This test validates a normal behavior (Alias Duplication) when the feature is disabled
     */
    @Test
    public void testDeDuplicatesIsNotEnable() throws Exception {

        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES_ENABLED, "false");
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES, "NVD;GITHUB");

        Component comp = setUp();

        assertThat(comp.getVulnerabilities()).extracting(Vulnerability::getVulnId)
        .contains("CVE-1234-123", "GHSA-002");

        Project clonedProject = qm.clone(project.getUuid(), "1.1.0", false, false, true, false, false, false, false);
        List<Finding> findings = qm.getFindings(clonedProject);

        Assert.assertEquals(2, findings.size());
    }

    /*
     * This test scenario is highly unlikely to occur because it is not possible
     * to have no enabled sources on the list and encounter vulnerabilities from other sources simultaneously.
     * The deduplication process will detect that the enabled sources (Priority List) is empty and will automatically change to false.
     */
    @Test
    public void testDeDuplicatesNoEnabledSources() throws Exception {
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES_ENABLED, "true");
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES, "");

        Component comp = setUp();

        assertThat(comp.getVulnerabilities()).extracting(Vulnerability::getVulnId)
        .contains("CVE-1234-123", "GHSA-002");

        Project clonedProject = qm.clone(project.getUuid(), "1.1.0", false, false, true, false, false, false, false);
        List<Finding> findings = qm.getFindings(clonedProject);

        Assert.assertEquals(2, findings.size());
    }

    /*
     * This test validates that the NVD (National Vulnerability Database) vulnerability source
     * has a higher priority than GHSA (GitHub Security Advisory).
     * The test ensures the avoidance of duplicate aliases in components.
     */
    @Test
    public void testAvoidAliasDuplicatesInComponentsNVDPriority() throws Exception {
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES_ENABLED, "true");
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES, "VULNDB;NVD;GITHUB");

        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED, "true");
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED, "true");
        createConfig(ConfigPropertyConstants.SCANNER_VULNDB_ENABLED, "true");
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_ENABLED, "true");

        Component comp = setUp();

        //Contains CVE, not GHSA
        assertThat(comp.getVulnerabilities()).extracting(Vulnerability::getVulnId)
        .containsOnly("CVE-1234-123")
        .doesNotContain("GHSA-002");

        Project clonedProject = qm.clone(project.getUuid(), "1.1.0", false, false, true, false, false, false, false);
        List<Finding> findings = qm.getFindings(clonedProject);

        Assert.assertEquals(1, findings.size());
    }

    /*
     * This test validates that the GHSA (GitHub Security Advisory) vulnerability source
     * has a higher priority than NVD (National Vulnerability Database).
     * The test ensures the avoidance of duplicate aliases in components.
     */
    @Test
    public void testAvoidAliasDuplicatesInComponentsGHSAPriority() throws Exception {
        //In this test GHSA source has a higher priority that NVD
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES_ENABLED, "true");
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES, "VULNDB;GITHUB;NVD");

        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED, "true");
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED, "true");
        createConfig(ConfigPropertyConstants.SCANNER_VULNDB_ENABLED, "true");
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_ENABLED, "true");

        Component comp = setUp();

        //Contains GHSA, not CVE
        assertThat(comp.getVulnerabilities()).extracting(Vulnerability::getVulnId)
        .containsOnly("GHSA-002")
        .doesNotContain("CVE-1234-123");

        Project clonedProject = qm.clone(project.getUuid(), "1.1.0", false, false, true, false, false, false, false);
        List<Finding> findings = qm.getFindings(clonedProject);

        Assert.assertEquals(1, findings.size());
    }

    /*
     * It is highly improbable for this test scenario to happen as it is not feasible to deactivate
     * a source and then encounter a vulnerability from that same source.
     */
    @Test
    public void testAvoidAliasDuplicatesInComponentsNonExistingPriority() throws Exception {
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES_ENABLED, "true");
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES, "VULNDB");

        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_ENABLED, "false");
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED, "false");
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED, "false");
        createConfig(ConfigPropertyConstants.SCANNER_VULNDB_ENABLED, "true");

        Component comp = setUp();
        // In the absence of a specified source in the priority list,
        //the initial vulnerability that gets added will persist,
        //while the others will merely serve as aliases for the first one.
        //This follows a "First Come, First Serve" approach.
         assertThat(comp.getVulnerabilities()).extracting(Vulnerability::getVulnId)
         .containsOnly("CVE-1234-123")
         .doesNotContain("GHSA-002");

        Project clonedProject = qm.clone(project.getUuid(), "1.1.0", false, false, true, false, false, false, false);
        List<Finding> findings = qm.getFindings(clonedProject);

        Assert.assertEquals(1, findings.size());
    }

    /*
     * This test verifies the behavior when enabling a new Vulnerability Source after setting
     * the priority list of vulnerability sources.
     */
    @Test
    public void testUpdatePriorityList() throws Exception {
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES_ENABLED, "true");
        //Source GITHUB is not initialy specified on the list
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES, "VULNDB");

        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_ENABLED, "false");
        //Github alias is enabled afterwards
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED, "true");
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED, "true");
        createConfig(ConfigPropertyConstants.SCANNER_VULNDB_ENABLED, "true");

        Component comp = setUp();

        //Priority list will be updated from VULNDB -> VULNDB;GITHUB
        //Only expecting a GITHUB Vulnerability
         assertThat(comp.getVulnerabilities()).extracting(Vulnerability::getVulnId)
         .containsOnly("GHSA-002")
         .doesNotContain("CVE-1234-123");

        Project clonedProject = qm.clone(project.getUuid(), "1.1.0", false, false, true, false, false, false, false);
        List<Finding> findings = qm.getFindings(clonedProject);

        Assert.assertEquals(1, findings.size());
    }

    /*
     * This test verifies the behavior when disabling the Vulnerability Source after setting
     * the priority list of vulnerability sources.
     */
    @Test
    public void testUpdatePriorityList2() throws Exception {
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES_ENABLED, "true");
        //PriorityList is specified, GITHUB has a higher priority than NVD
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES, "VULNDB;GITHUB;NVD");
        //Shortly after the admin decided to not allow GITHUB SOURCES anymore
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED, "true");
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED, "false");
        //NVD is still enabled
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_ENABLED, "true");
        createConfig(ConfigPropertyConstants.SCANNER_VULNDB_ENABLED, "true");

        Component comp = setUp();

        //Priority list will be updated from "VULNDB;GITHUB;NVD" -> "VULNDB;NVD"
        //Giving NVD a higher priority and not expecting any GITHUB vulnerability
         assertThat(comp.getVulnerabilities()).extracting(Vulnerability::getVulnId)
         .containsOnly("CVE-1234-123")
         .doesNotContain("GHSA-002");

        Project clonedProject = qm.clone(project.getUuid(), "1.1.0", false, false, true, false, false, false, false);
        List<Finding> findings = qm.getFindings(clonedProject);

        Assert.assertEquals(1, findings.size());
    }

    /*
     *  This test verifies the behavior when avoiding duplicate aliases for vulnerabilities added later.
     */
    @Test
    public void testAvoidAliasDuplicatesVulnerabilityAddedLater() throws Exception {
        Vulnerability vuln3 = new Vulnerability();
        List<VulnerabilityAlias> vulnerabilityAliases = new ArrayList<>();

        vulnerabilityAliases.add(alias);

        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES_ENABLED, "true");
        createConfig(ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES, "OSSINDEX;GITHUB;NVD");

        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED, "true");
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED, "true");
        createConfig(ConfigPropertyConstants.SCANNER_OSSINDEX_ENABLED, "true");
        createConfig(ConfigPropertyConstants.SCANNER_OSSINDEX_ALIAS_SYNC_ENABLED, "true");
        createConfig(ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_ENABLED, "true");

        Component comp = setUp();

        //Contains GHSA, not CVE
        assertThat(comp.getVulnerabilities()).extracting(Vulnerability::getVulnId)
        .containsOnly("GHSA-002")
        .doesNotContain("CVE-1234-123");

        vuln3.setId(128L);
        vuln3.setVulnId("SONATYPE-003");
        vuln3.setSource(Vulnerability.Source.OSSINDEX);
        vuln3.setSeverity(Severity.HIGH);
        vuln3.setAliases(vulnerabilityAliases);
        qm.persist(vuln3);

        qm.addVulnerability(vuln3, comp, AnalyzerIdentity.INTERNAL_ANALYZER, "Vuln2", "http://vuln.com/vuln", new Date(1708559165229L));

        //Although OSSINDEX has a higher priority GITHUB was already added to the component, avoiding a duplication
        assertThat(comp.getVulnerabilities()).extracting(Vulnerability::getVulnId)
        .containsOnly("GHSA-002")
        .doesNotContain("CVE-1234-123")
        .doesNotContain("SONATYPE-003");

        Project clonedProject = qm.clone(project.getUuid(), "1.1.0", false, false, true, false, false, false, false);
        List<Finding> findings = qm.getFindings(clonedProject);

        Assert.assertEquals(1, findings.size());
    }
}