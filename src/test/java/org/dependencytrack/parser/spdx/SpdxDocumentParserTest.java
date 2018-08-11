/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.parser.spdx;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.dependencytrack.BaseTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.parser.spdx.rdf.SpdxDocumentParser;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.dependencytrack.persistence.QueryManager;

import java.util.List;

public class SpdxDocumentParserTest extends BaseTest {

    @Before
    public void loadDefaultLicenses() {
        DefaultObjectGenerator dog = new DefaultObjectGenerator();
        dog.contextInitialized(null);
    }

    @Test
    public void testSpdxRdf21() throws Exception {
        try (QueryManager qm = new QueryManager()) {
            final SpdxDocumentParser parser = new SpdxDocumentParser(qm);
            final byte[] bom = IOUtils.toByteArray(this.getClass().getResourceAsStream("/SPDXRdfExample-v2.1.rdf"));
            final List<Component> components = parser.parse(bom);
            Assert.assertEquals(6, components.size());
            for (int i = 0; i < components.size(); i++) {
                final Component component = components.get(i);
                Assert.assertNotNull(component);
                if (i == 0) {
                    validateSaxon(component);
                } else if (i == 1) {
                    validateGlibc(component);
                } else if (i == 2) {
                    validateJenaFoo(component);
                } else if (i == 3) {
                    validateCommonsLang(component);
                } else if (i == 4) {
                    validateJenaSources(component);
                } else if (i == 5) {
                    validateDoapProject(component);
                }
            }
        }
    }

    @Test
    public void testSpdxTag21() throws Exception {
        try (QueryManager qm = new QueryManager()) {
            final SpdxDocumentParser parser = new SpdxDocumentParser(qm);
            final byte[] bom = IOUtils.toByteArray(this.getClass().getResourceAsStream("/SPDXTagExample-v2.1.spdx"));
            final List<Component> components = parser.parse(bom);
            Assert.assertEquals(6, components.size());
            for (int i = 0; i < components.size(); i++) {
                final Component component = components.get(i);
                Assert.assertNotNull(component);
                if (i == 0) {
                    validateSaxon(component);
                } else if (i == 1) {
                    validateGlibc(component);
                } else if (i == 2) {
                    validateDoapProject(component);
                } else if (i == 3) {
                    validateJenaSources(component);
                } else if (i == 4) {
                    validateCommonsLang(component);
                } else if (i == 5) {
                    validateJenaFoo(component);
                }
            }
        }
    }

    /**
     * Saxon is defined as an SPDX Package.
     */
    private void validateSaxon(Component component) {
        Assert.assertNull(component.getGroup());
        Assert.assertEquals("Saxon", component.getName());
        Assert.assertEquals("8.8", component.getVersion());
        Assert.assertEquals("saxonB-8.8.zip", component.getFilename());
        Assert.assertNull(component.getMd5());
        Assert.assertEquals("85ed0817af83a24ad8da68c2b5094de69833983c", component.getSha1());
        Assert.assertNull(component.getSha256());
        Assert.assertNull(component.getSha512());
        Assert.assertNull(component.getSha3_256());
        Assert.assertNull(component.getSha3_512());
        Assert.assertNull(component.getClassifier());
        Assert.assertNull(component.getExtension());
        Assert.assertNull(component.getPurl());
        Assert.assertTrue(component.getDescription().startsWith("The Saxon package"));
        Assert.assertNull(component.getLicense());
        Assert.assertEquals("Copyright Saxonica Ltd", component.getCopyright());
        Assert.assertNotNull(component.getResolvedLicense());
        Assert.assertNull(component.getParent());
        Assert.assertNull(component.getChildren());
        Assert.assertNull(component.getEvidence());
        Assert.assertNull(component.getScans());
        Assert.assertNull(component.getVulnerabilities());
        Assert.assertNull(component.getUuid());
    }

    /**
     * GlibC is defined as an SPDX Package.
     */
    private void validateGlibc(Component component) {
        Assert.assertEquals("Organization: ExampleCodeInspect (contact@example.com)", component.getGroup());
        Assert.assertEquals("glibc", component.getName());
        Assert.assertEquals("2.11.1", component.getVersion());
        Assert.assertEquals("glibc-2.11.1.tar.gz", component.getFilename());
        Assert.assertEquals("624c1abb3664f4b35547e7c73864ad24", component.getMd5());
        Assert.assertEquals("85ed0817af83a24ad8da68c2b5094de69833983c", component.getSha1());
        Assert.assertEquals("11b6d3ee554eedf79299905a98f9b9a04e498210b59f15094c916c91d150efcd", component.getSha256());
        Assert.assertNull(component.getSha512());
        Assert.assertNull(component.getSha3_256());
        Assert.assertNull(component.getSha3_512());
        Assert.assertNull(component.getClassifier());
        Assert.assertNull(component.getExtension());
        Assert.assertNull(component.getPurl());
        Assert.assertTrue(component.getDescription().startsWith("The GNU C Library"));
        Assert.assertEquals("Copyright 2008-2010 John Smith", component.getCopyright());
        Assert.assertEquals("CyberNeko License", component.getLicense());
        Assert.assertNotNull(component.getResolvedLicense());
        Assert.assertNull(component.getParent());
        Assert.assertNull(component.getChildren());
        Assert.assertNull(component.getEvidence());
        Assert.assertNull(component.getScans());
        Assert.assertNull(component.getVulnerabilities());
        Assert.assertNull(component.getUuid());
    }

    /**
     * DoapProject is defined as an SPDX File.
     */
    private void validateDoapProject(Component component) {
        Assert.assertNull(component.getGroup());
        Assert.assertEquals("./src/org/spdx/parser/DOAPProject.java", component.getName());
        Assert.assertNull(component.getVersion());
        Assert.assertEquals("./src/org/spdx/parser/DOAPProject.java", component.getFilename());
        Assert.assertNull(component.getMd5());
        Assert.assertEquals("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", component.getSha1());
        Assert.assertNull(component.getSha256());
        Assert.assertNull(component.getSha512());
        Assert.assertNull(component.getSha3_256());
        Assert.assertNull(component.getSha3_512());
        Assert.assertNull(component.getClassifier());
        Assert.assertNull(component.getExtension());
        Assert.assertNull(component.getPurl());
        Assert.assertNull(component.getDescription());
        Assert.assertEquals("Copyright 2010, 2011 Source Auditor Inc.", component.getCopyright());
        Assert.assertNull(component.getLicense());
        Assert.assertNotNull(component.getResolvedLicense());
        Assert.assertNull(component.getParent());
        Assert.assertNull(component.getChildren());
        Assert.assertNull(component.getEvidence());
        Assert.assertNull(component.getScans());
        Assert.assertNull(component.getVulnerabilities());
        Assert.assertNull(component.getUuid());
    }

    /**
     * Jena foo.c is defined as an SPDX File.
     */
    private void validateJenaFoo(Component component) {
        Assert.assertNull(component.getGroup());
        Assert.assertEquals("Jena", component.getName());
        Assert.assertNull(component.getVersion());
        Assert.assertEquals("./package/foo.c", component.getFilename());
        Assert.assertEquals("624c1abb3664f4b35547e7c73864ad24", component.getMd5());
        Assert.assertEquals("d6a770ba38583ed4bb4525bd96e50461655d2758", component.getSha1());
        Assert.assertNull(component.getSha256());
        Assert.assertNull(component.getSha512());
        Assert.assertNull(component.getSha3_256());
        Assert.assertNull(component.getSha3_512());
        Assert.assertNull(component.getClassifier());
        Assert.assertNull(component.getExtension());
        Assert.assertNull(component.getPurl());
        Assert.assertNull(component.getDescription());
        Assert.assertEquals("Copyright 2008-2010 John Smith", component.getCopyright());
        Assert.assertNull(component.getLicense());
        Assert.assertNull(component.getResolvedLicense());
        Assert.assertNull(component.getParent());
        Assert.assertNull(component.getChildren());
        Assert.assertNull(component.getEvidence());
        Assert.assertNull(component.getScans());
        Assert.assertNull(component.getVulnerabilities());
        Assert.assertNull(component.getUuid());
    }

    /**
     * Jena sources is defined as an SPDX File.
     */
    private void validateJenaSources(Component component) {
        Assert.assertNull(component.getGroup());
        Assert.assertEquals("Jena", component.getName());
        Assert.assertNull(component.getVersion());
        Assert.assertEquals("./lib-source/jena-2.6.3-sources.jar", component.getFilename());
        Assert.assertNull(component.getMd5());
        Assert.assertEquals("3ab4e1c67a2d28fced849ee1bb76e7391b93f125", component.getSha1());
        Assert.assertNull(component.getSha256());
        Assert.assertNull(component.getSha512());
        Assert.assertNull(component.getSha3_256());
        Assert.assertNull(component.getSha3_512());
        Assert.assertNull(component.getClassifier());
        Assert.assertNull(component.getExtension());
        Assert.assertNull(component.getPurl());
        Assert.assertNull(component.getDescription());
        Assert.assertEquals("(c) Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Hewlett-Packard Development Company, LP", component.getCopyright());
        Assert.assertNull(component.getLicense());
        Assert.assertNull(component.getResolvedLicense());
        Assert.assertNull(component.getParent());
        Assert.assertNull(component.getChildren());
        Assert.assertNull(component.getEvidence());
        Assert.assertNull(component.getScans());
        Assert.assertNull(component.getVulnerabilities());
        Assert.assertNull(component.getUuid());
    }

    /**
     * x.java is defined as an SPDX File.
     */
    private void validateJavaX(Component component) {
        Assert.assertNull(component.getGroup());
        Assert.assertEquals("./src/org/spdx/parser/x   .java", component.getName());
        Assert.assertNull(component.getVersion());
        Assert.assertEquals("./src/org/spdx/parser/x   .java", component.getFilename());
        Assert.assertNull(component.getMd5());
        Assert.assertEquals("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", component.getSha1());
        Assert.assertNull(component.getSha256());
        Assert.assertNull(component.getSha512());
        Assert.assertNull(component.getSha3_256());
        Assert.assertNull(component.getSha3_512());
        Assert.assertNull(component.getClassifier());
        Assert.assertNull(component.getExtension());
        Assert.assertNull(component.getPurl());
        Assert.assertNull(component.getDescription());
        Assert.assertEquals("Copyright 2010, 2011 Source Auditor Inc.", component.getCopyright());
        Assert.assertNull(component.getLicense());
        Assert.assertNotNull(component.getResolvedLicense());
        Assert.assertNull(component.getParent());
        Assert.assertNull(component.getChildren());
        Assert.assertNull(component.getEvidence());
        Assert.assertNull(component.getScans());
        Assert.assertNull(component.getVulnerabilities());
        Assert.assertNull(component.getUuid());
    }

    /**
     * Commons Lang is defined as an SPDX File.
     */
    private void validateCommonsLang(Component component) {
        Assert.assertNull(component.getGroup());
        Assert.assertEquals("Apache Commons Lang", component.getName());
        Assert.assertNull(component.getVersion());
        Assert.assertEquals("./lib-source/commons-lang3-3.1-sources.jar", component.getFilename());
        Assert.assertNull(component.getMd5());
        Assert.assertEquals("c2b4e1c67a2d28fced849ee1bb76e7391b93f125", component.getSha1());
        Assert.assertNull(component.getSha256());
        Assert.assertNull(component.getSha512());
        Assert.assertNull(component.getSha3_256());
        Assert.assertNull(component.getSha3_512());
        Assert.assertNull(component.getClassifier());
        Assert.assertNull(component.getExtension());
        Assert.assertNull(component.getPurl());
        Assert.assertNull(component.getDescription());
        Assert.assertEquals("Copyright 2001-2011 The Apache Software Foundation", component.getCopyright());
        Assert.assertNull(component.getLicense());
        Assert.assertNotNull(component.getResolvedLicense());
        Assert.assertNull(component.getParent());
        Assert.assertNull(component.getChildren());
        Assert.assertNull(component.getEvidence());
        Assert.assertNull(component.getScans());
        Assert.assertNull(component.getVulnerabilities());
        Assert.assertNull(component.getUuid());
    }
}
