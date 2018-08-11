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
package org.dependencytrack.parser.cyclonedx;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.dependencytrack.BaseTest;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.parser.cyclonedx.model.Bom;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.dependencytrack.persistence.QueryManager;
import java.util.List;

public class CycloneDxParserTest extends BaseTest {

    @Before
    public void loadDefaultLicenses() {
        DefaultObjectGenerator dog = new DefaultObjectGenerator();
        dog.contextInitialized(null);
    }

    @Test
    public void testValidBom() throws Exception {
        try (QueryManager qm = new QueryManager()) {
            final CycloneDxParser parser = new CycloneDxParser(qm);
            final byte[] bomBytes = IOUtils.toByteArray(this.getClass().getResourceAsStream("/bom.xml"));
            final Bom bom = parser.parse(bomBytes);
            Assert.assertEquals(1, bom.getComponents().size());
            Assert.assertEquals(1, bom.getVersion());
            final List<Component> components = parser.convert(bom);

            Assert.assertEquals(1, components.size());

            Component c1 = components.get(0);
            Assert.assertEquals("org.example", c1.getGroup());
            Assert.assertEquals("1.0.0", c1.getVersion());
            Assert.assertEquals(Classifier.APPLICATION, c1.getClassifier());
            Assert.assertEquals("2342c2eaf1feb9a80195dbaddf2ebaa3", c1.getMd5());
            Assert.assertEquals("68b78babe00a053f9e35ec6a2d9080f5b90122b0", c1.getSha1());
            Assert.assertEquals("708f1f53b41f11f02d12a11b1a38d2905d47b099afc71a0f1124ef8582ec7313", c1.getSha256());
            Assert.assertEquals("387b7ae16b9cae45f830671541539bf544202faae5aac544a93b7b0a04f5f846fa2f4e81ef3f1677e13aed7496408a441f5657ab6d54423e56bf6f38da124aef", c1.getSha512());
            Assert.assertEquals("cpe:/a:example:myapplication:1.0.0", c1.getCpe());
            Assert.assertEquals("pkg:maven/com.example/myapplication@1.0.0?packaging=war", c1.getPurl().canonicalize());
            Assert.assertEquals("An example application", c1.getDescription());
            Assert.assertEquals("Copyright Example Inc. All rights reserved.", c1.getCopyright());
            Assert.assertEquals("Apache-2.0", c1.getResolvedLicense().getLicenseId());
            Assert.assertEquals(2, c1.getChildren().size());
        }
    }

}
