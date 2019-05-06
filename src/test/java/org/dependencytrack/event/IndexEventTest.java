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
package org.dependencytrack.event;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.junit.Assert;
import org.junit.Test;

public class IndexEventTest {

    @Test
    public void testProjectEvent() {
        Project project = new Project();
        IndexEvent event = new IndexEvent(IndexEvent.Action.CREATE, project);
        Assert.assertEquals(IndexEvent.Action.CREATE, event.getAction());
        Assert.assertEquals(project, event.getObject());
        Assert.assertNull(event.getIndexableClass());
    }

    @Test
    public void testComponentEvent() {
        Component component = new Component();
        IndexEvent event = new IndexEvent(IndexEvent.Action.UPDATE, component);
        Assert.assertEquals(IndexEvent.Action.UPDATE, event.getAction());
        Assert.assertEquals(component, event.getObject());
        Assert.assertNull(event.getIndexableClass());
    }

    @Test
    public void testVulnerabilityEvent() {
        Vulnerability vulnerability = new Vulnerability();
        IndexEvent event = new IndexEvent(IndexEvent.Action.DELETE, vulnerability);
        Assert.assertEquals(IndexEvent.Action.DELETE, event.getAction());
        Assert.assertEquals(vulnerability, event.getObject());
        Assert.assertNull(event.getIndexableClass());
    }

    @Test
    public void testLicenseEvent() {
        License license = new License();
        IndexEvent event = new IndexEvent(IndexEvent.Action.COMMIT, license);
        Assert.assertEquals(IndexEvent.Action.COMMIT, event.getAction());
        Assert.assertEquals(license, event.getObject());
        Assert.assertNull(event.getIndexableClass());
    }

    @Test
    public void testClassEvent() {
        Class clazz = License.class;
        IndexEvent event = new IndexEvent(IndexEvent.Action.REINDEX, clazz);
        Assert.assertEquals(IndexEvent.Action.REINDEX, event.getAction());
        Assert.assertNull(event.getObject());
        Assert.assertEquals(clazz, event.getIndexableClass());
    }

    @Test
    public void testActions() {
        Assert.assertEquals(5, IndexEvent.Action.values().length);
        Assert.assertEquals("CREATE", IndexEvent.Action.CREATE.name());
        Assert.assertEquals("UPDATE", IndexEvent.Action.UPDATE.name());
        Assert.assertEquals("DELETE", IndexEvent.Action.DELETE.name());
        Assert.assertEquals("COMMIT", IndexEvent.Action.COMMIT.name());
        Assert.assertEquals("REINDEX", IndexEvent.Action.REINDEX.name());
    }
}
