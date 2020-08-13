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
package org.dependencytrack.model;

import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.junit.Assert;
import org.junit.Test;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class ComponentTest {

    @Test
    public void testId() {
        Component component = new Component();
        component.setId(111L);
        Assert.assertEquals(111L, component.getId());
    }

    @Test
    public void testGroup() {
        Component component = new Component();
        component.setGroup("group");
        Assert.assertEquals("group", component.getGroup());
    }

    @Test
    public void testName() {
        Component component = new Component();
        component.setName("name");
        Assert.assertEquals("name", component.getName());
    }

    @Test
    public void testVersion() {
        Component component = new Component();
        component.setVersion("1.0");
        Assert.assertEquals("1.0", component.getVersion());
    }

    @Test
    public void testClassifier() {
        Component component = new Component();
        component.setClassifier(Classifier.LIBRARY);
        Assert.assertEquals(Classifier.LIBRARY, component.getClassifier());
    }

    @Test
    public void testFilename() {
        Component component = new Component();
        component.setFilename("foo.bar");
        Assert.assertEquals("foo.bar", component.getFilename());
    }

    @Test
    public void testExtension() {
        Component component = new Component();
        component.setExtension("bar");
        Assert.assertEquals("bar", component.getExtension());
    }

    @Test
    public void testMd5() {
        Component component = new Component();
        String hash = "299189766eddf8b5fea4954f0a63d4b1";
        component.setMd5(hash);
        Assert.assertEquals(hash, component.getMd5());
    }

    @Test
    public void testSha1() {
        Component component = new Component();
        String hash = "74f7fcc24e02e61b0eb367e273139b6b24c6587f";
        component.setSha1(hash);
        Assert.assertEquals(hash, component.getSha1());
    }

    @Test
    public void testSha256()  {
        Component component = new Component();
        String hash = "cfb16d5a50169bac7699d6fc1ad4f8f2559d09e3fa580003b149ae0134e16d05";
        component.setSha256(hash);
        Assert.assertEquals(hash, component.getSha256());
    }

    @Test
    public void testSha512() {
        Component component = new Component();
        String hash = "d52e762d8e1b8a33c7f7b4b2ab356a02d43e6bf51d273a5809a3478dc47f17b6df350890d06bb0240a7d3f51f49dde564a32f569952c8b02f54242cc3f92d277";
        component.setSha512(hash);
        Assert.assertEquals(hash, component.getSha512());
    }

    @Test
    public void testSha3_256() {
        Component component = new Component();
        String hash = "b59bf7eba413502f563528a9719c38cd471ca59b4fb50c1d94db0504101ea780";
        component.setSha3_256(hash);
        Assert.assertEquals(hash, component.getSha3_256());
    }

    @Test
    public void testSha3_512() {
        Component component = new Component();
        String hash = "40c72266a83cb97e6c5dbe628d3efb7fe564739e7d4c016d282c59ae14054ccd74142defa2d5d0295c7bdff0d1ea045364a595438263dd8ffd13623a685034e1";
        component.setSha3_512(hash);
        Assert.assertEquals(hash, component.getSha3_512());
    }

    @Test
    public void testCpe() throws Exception {
        Component component = new Component();
        Cpe cpe = CpeParser.parse("cpe:2.3:a:acme:product:1.0:*:*:*:*:*:*:*");
        component.setCpe(cpe.toCpe23FS());
        Assert.assertEquals("cpe:2.3:a:acme:product:1.0:*:*:*:*:*:*:*", component.getCpe());
    }

    @Test
    public void testPurl() throws Exception {
        Component component = new Component();
        PackageURL purl = PackageURLBuilder.aPackageURL()
                .withType("maven").withNamespace("acme").withName("product").withVersion("1.0").build();
        component.setPurl(purl);
        Assert.assertEquals(purl.toString(), component.getPurl().toString());
    }

    @Test
    public void testDescription() {
        Component component = new Component();
        component.setDescription("Component description");
        Assert.assertEquals("Component description", component.getDescription());
    }

    @Test
    public void testCopyright() {
        Component component = new Component();
        component.setCopyright("Copyright Acme");
        Assert.assertEquals("Copyright Acme", component.getCopyright());
    }

    @Test
    public void testLicense() {
        Component component = new Component();
        component.setLicense("Apache 2.0");
        Assert.assertEquals("Apache 2.0", component.getLicense());
    }

    @Test
    public void testResolvedLicense() {
        License license = new License();
        Component component = new Component();
        component.setResolvedLicense(license);
        Assert.assertEquals(license, component.getResolvedLicense());
    }

    @Test
    public void testParent() {
        Component parent = new Component();
        Component component = new Component();
        component.setParent(parent);
        Assert.assertEquals(parent, component.getParent());
    }

    @Test
    public void testChildren() {
        List<Component> children = new ArrayList<>();
        Component child = new Component();
        children.add(child);
        Component component = new Component();
        component.setChildren(children);
        Assert.assertEquals(1, component.getChildren().size());
        Assert.assertEquals(child, component.getChildren().iterator().next());
    }

    @Test
    public void testVulnerabilities() {
        List<Vulnerability> vulns = new ArrayList<>();
        Vulnerability vuln = new Vulnerability();
        vulns.add(vuln);
        Component component = new Component();
        component.setVulnerabilities(vulns);
        Assert.assertEquals(1, component.getVulnerabilities().size());
        Assert.assertEquals(vuln, component.getVulnerabilities().iterator().next());
    }

    @Test
    public void testUuid() {
        UUID uuid = UUID.randomUUID();
        Component component = new Component();
        component.setUuid(uuid);
        Assert.assertEquals(uuid.toString(), component.getUuid().toString());
    }

    @Test
    public void testToStringWithPurl() throws Exception {
        Component component = new Component();
        PackageURL purl = PackageURLBuilder.aPackageURL()
                .withType("maven").withNamespace("acme").withName("product").withVersion("1.0").build();
        component.setPurl(purl);
        Assert.assertEquals(component.getPurl().toString(), component.toString());
    }

    @Test
    public void testToStringWithoutPurl() {
        Component component = new Component();
        component.setGroup("acme");
        component.setName("product");
        component.setVersion("1.0");
        Assert.assertEquals("acme : product : 1.0", component.toString());
    }
}
