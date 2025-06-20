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
package org.dependencytrack.event;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.search.document.ComponentDocument;
import org.dependencytrack.search.document.LicenseDocument;
import org.dependencytrack.search.document.ProjectDocument;
import org.dependencytrack.search.document.VulnerabilityDocument;
import org.dependencytrack.search.document.VulnerableSoftwareDocument;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class IndexEventTest {

    @Test
    void testProjectEvent() {
        Project project = new Project();
        IndexEvent event = new IndexEvent(IndexEvent.Action.CREATE, project);
        Assertions.assertEquals(IndexEvent.Action.CREATE, event.getAction());
        Assertions.assertEquals(new ProjectDocument(project), event.getDocument());
        Assertions.assertEquals(Project.class, event.getIndexableClass());
    }

    @Test
    void testComponentEvent() {
        Component component = new Component();
        IndexEvent event = new IndexEvent(IndexEvent.Action.UPDATE, component);
        Assertions.assertEquals(IndexEvent.Action.UPDATE, event.getAction());
        Assertions.assertEquals(new ComponentDocument(component), event.getDocument());
        Assertions.assertEquals(Component.class, event.getIndexableClass());
    }

    @Test
    void testVulnerabilityEvent() {
        Vulnerability vulnerability = new Vulnerability();
        IndexEvent event = new IndexEvent(IndexEvent.Action.DELETE, vulnerability);
        Assertions.assertEquals(IndexEvent.Action.DELETE, event.getAction());
        Assertions.assertEquals(new VulnerabilityDocument(vulnerability), event.getDocument());
        Assertions.assertEquals(Vulnerability.class, event.getIndexableClass());
    }

    @Test
    void testLicenseEvent() {
        License license = new License();
        IndexEvent event = new IndexEvent(IndexEvent.Action.COMMIT, license);
        Assertions.assertEquals(IndexEvent.Action.COMMIT, event.getAction());
        Assertions.assertEquals(new LicenseDocument(license), event.getDocument());
        Assertions.assertEquals(License.class, event.getIndexableClass());
    }

    @Test
    void testVulnerableSoftwareEvent() {
        VulnerableSoftware vulnerableSoftware = new VulnerableSoftware();
        IndexEvent event = new IndexEvent(IndexEvent.Action.COMMIT, vulnerableSoftware);
        Assertions.assertEquals(IndexEvent.Action.COMMIT, event.getAction());
        Assertions.assertEquals(new VulnerableSoftwareDocument(vulnerableSoftware), event.getDocument());
        Assertions.assertEquals(VulnerableSoftware.class, event.getIndexableClass());
    }

    @Test
    void testClassEvent() {
        Class clazz = License.class;
        IndexEvent event = new IndexEvent(IndexEvent.Action.REINDEX, clazz);
        Assertions.assertEquals(IndexEvent.Action.REINDEX, event.getAction());
        Assertions.assertNull(event.getDocument());
        Assertions.assertEquals(clazz, event.getIndexableClass());
    }

    @Test
    void testActions() {
        Assertions.assertEquals(6, IndexEvent.Action.values().length);
        Assertions.assertEquals("CREATE", IndexEvent.Action.CREATE.name());
        Assertions.assertEquals("UPDATE", IndexEvent.Action.UPDATE.name());
        Assertions.assertEquals("DELETE", IndexEvent.Action.DELETE.name());
        Assertions.assertEquals("COMMIT", IndexEvent.Action.COMMIT.name());
        Assertions.assertEquals("REINDEX", IndexEvent.Action.REINDEX.name());
        Assertions.assertEquals("CHECK", IndexEvent.Action.CHECK.name());
    }
}
