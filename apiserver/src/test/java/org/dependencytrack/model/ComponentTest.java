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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.dependencytrack.PersistenceCapableTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;

import javax.jdo.JDOObjectNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

public class ComponentTest extends PersistenceCapableTest {

    @Test
    void testId() {
        Component component = new Component();
        component.setId(111L);
        Assertions.assertEquals(111L, component.getId());
    }

    @Test
    void testGroup() {
        Component component = new Component();
        component.setGroup("group");
        Assertions.assertEquals("group", component.getGroup());
    }

    @Test
    void testName() {
        Component component = new Component();
        component.setName("name");
        Assertions.assertEquals("name", component.getName());
    }

    @Test
    void testVersion() {
        Component component = new Component();
        component.setVersion("1.0");
        Assertions.assertEquals("1.0", component.getVersion());
    }

    @Test
    void testClassifier() {
        Component component = new Component();
        component.setClassifier(Classifier.LIBRARY);
        Assertions.assertEquals(Classifier.LIBRARY, component.getClassifier());
    }

    @Test
    void testFilename() {
        Component component = new Component();
        component.setFilename("foo.bar");
        Assertions.assertEquals("foo.bar", component.getFilename());
    }

    @Test
    void testExtension() {
        Component component = new Component();
        component.setExtension("bar");
        Assertions.assertEquals("bar", component.getExtension());
    }

    @Test
    void testMd5() {
        Component component = new Component();
        String hash = "299189766eddf8b5fea4954f0a63d4b1";
        component.setMd5(hash);
        Assertions.assertEquals(hash, component.getMd5());
    }

    @Test
    void testSha1() {
        Component component = new Component();
        String hash = "74f7fcc24e02e61b0eb367e273139b6b24c6587f";
        component.setSha1(hash);
        Assertions.assertEquals(hash, component.getSha1());
    }

    @Test
    void testSha256()  {
        Component component = new Component();
        String hash = "cfb16d5a50169bac7699d6fc1ad4f8f2559d09e3fa580003b149ae0134e16d05";
        component.setSha256(hash);
        Assertions.assertEquals(hash, component.getSha256());
    }

    @Test
    void testSha512() {
        Component component = new Component();
        String hash = "d52e762d8e1b8a33c7f7b4b2ab356a02d43e6bf51d273a5809a3478dc47f17b6df350890d06bb0240a7d3f51f49dde564a32f569952c8b02f54242cc3f92d277";
        component.setSha512(hash);
        Assertions.assertEquals(hash, component.getSha512());
    }

    @Test
    void testSha3_256() {
        Component component = new Component();
        String hash = "b59bf7eba413502f563528a9719c38cd471ca59b4fb50c1d94db0504101ea780";
        component.setSha3_256(hash);
        Assertions.assertEquals(hash, component.getSha3_256());
    }

    @Test
    void testSha3_512() {
        Component component = new Component();
        String hash = "40c72266a83cb97e6c5dbe628d3efb7fe564739e7d4c016d282c59ae14054ccd74142defa2d5d0295c7bdff0d1ea045364a595438263dd8ffd13623a685034e1";
        component.setSha3_512(hash);
        Assertions.assertEquals(hash, component.getSha3_512());
    }

    @Test
    void testCpe() throws Exception {
        Component component = new Component();
        Cpe cpe = CpeParser.parse("cpe:2.3:a:acme:product:1.0:*:*:*:*:*:*:*");
        component.setCpe(cpe.toCpe23FS());
        Assertions.assertEquals("cpe:2.3:a:acme:product:1.0:*:*:*:*:*:*:*", component.getCpe());
    }

    @Test
    void testPurl() throws Exception {
        Component component = new Component();
        PackageURL purl = PackageURLBuilder.aPackageURL()
                .withType("maven").withNamespace("acme").withName("product").withVersion("1.0").build();
        component.setPurl(purl);
        Assertions.assertEquals(purl.toString(), component.getPurl().toString());
    }

    @Test
    void testDescription() {
        Component component = new Component();
        component.setDescription("Component description");
        Assertions.assertEquals("Component description", component.getDescription());
    }

    @Test
    void testCopyright() {
        Component component = new Component();
        component.setCopyright("Copyright Acme");
        Assertions.assertEquals("Copyright Acme", component.getCopyright());
    }

    @Test
    void testLicense() {
        Component component = new Component();
        component.setLicense("Apache 2.0");
        Assertions.assertEquals("Apache 2.0", component.getLicense());
    }

    @Test
    void testResolvedLicense() {
        License license = new License();
        Component component = new Component();
        component.setResolvedLicense(license);
        Assertions.assertEquals(license, component.getResolvedLicense());
    }

    @Test
    void testParent() {
        Component parent = new Component();
        Component component = new Component();
        component.setParent(parent);
        Assertions.assertEquals(parent, component.getParent());
    }

    @Test
    void testChildren() {
        List<Component> children = new ArrayList<>();
        Component child = new Component();
        children.add(child);
        Component component = new Component();
        component.setChildren(children);
        Assertions.assertEquals(1, component.getChildren().size());
        Assertions.assertEquals(child, component.getChildren().iterator().next());
    }

    @Test
    void testVulnerabilities() {
        List<Vulnerability> vulns = new ArrayList<>();
        Vulnerability vuln = new Vulnerability();
        vulns.add(vuln);
        Component component = new Component();
        component.setVulnerabilities(vulns);
        Assertions.assertEquals(1, component.getVulnerabilities().size());
        Assertions.assertEquals(vuln, component.getVulnerabilities().iterator().next());
    }

    @Test
    void testUuid() {
        UUID uuid = UUID.randomUUID();
        Component component = new Component();
        component.setUuid(uuid);
        Assertions.assertEquals(uuid.toString(), component.getUuid().toString());
    }

    @Test
    void testToStringWithPurl() throws Exception {
        Component component = new Component();
        PackageURL purl = PackageURLBuilder.aPackageURL()
                .withType("maven").withNamespace("acme").withName("product").withVersion("1.0").build();
        component.setPurl(purl);
        Assertions.assertEquals(component.getPurl().toString(), component.toString());
    }

    @Test
    void testToStringWithoutPurl() {
        Component component = new Component();
        component.setGroup("acme");
        component.setName("product");
        component.setVersion("1.0");
        Assertions.assertEquals("acme : product : 1.0", component.toString());
    }

    @Test
    public void shouldCascadeDeleteOfProject() {
        final var project = new Project();
        project.setName("project");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("component");
        qm.persist(component);

        qm.delete(project);

        qm.getPersistenceManager().evictAll();

        assertThatExceptionOfType(JDOObjectNotFoundException.class)
                .isThrownBy(() -> qm.getObjectById(Project.class, project.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class)
                .isThrownBy(() -> qm.getObjectById(Component.class, component.getId()));
    }

    @Test
    public void shouldCascadeDeleteOfParent() {
        final var project = new Project();
        project.setName("project");
        qm.persist(project);

        final var parentComponent = new Component();
        parentComponent.setProject(project);
        parentComponent.setName("parent");
        qm.persist(parentComponent);

        final var childComponent = new Component();
        childComponent.setProject(project);
        childComponent.setParent(parentComponent);
        childComponent.setName("child");
        qm.persist(childComponent);

        qm.delete(parentComponent);

        qm.getPersistenceManager().evictAll();

        assertThat(qm.getObjectById(Project.class, project.getId())).isNotNull();
        assertThatExceptionOfType(JDOObjectNotFoundException.class)
                .isThrownBy(() -> qm.getObjectById(Component.class, parentComponent.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class)
                .isThrownBy(() -> qm.getObjectById(Component.class, childComponent.getId()));
    }

}
