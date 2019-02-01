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
package org.dependencytrack.model; 

import org.junit.Assert;
import org.junit.Test;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class ScanTest { 

    @Test
    public void testId() { 
        Scan scan = new Scan();
        scan.setId(111L);
        Assert.assertEquals(111L, scan.getId());
    } 

    @Test
    public void testExecuted() {
        Date date = new Date();
        Scan scan = new Scan();
        scan.setExecuted(date);
        Assert.assertEquals(date, scan.getExecuted());
    } 

    @Test
    public void testImported() {
        Date date = new Date();
        Scan scan = new Scan();
        scan.setImported(date);
        Assert.assertEquals(date, scan.getImported());
    } 

    @Test
    public void testProject() {
        Project project = new Project();
        Scan scan = new Scan();
        scan.setProject(project);
        Assert.assertEquals(project, scan.getProject());
    } 

    @Test
    public void testComponents() {
        List<Component> components = new ArrayList<>();
        Component component = new Component();
        components.add(component);
        Scan scan = new Scan();
        scan.setComponents(components);
        Assert.assertEquals(1, scan.getComponents().size());
        Assert.assertEquals(component, scan.getComponents().get(0));
    } 

    @Test
    public void testUuid() {
        UUID uuid = UUID.randomUUID();
        Scan scan = new Scan();
        scan.setUuid(uuid);
        Assert.assertEquals(uuid.toString(), scan.getUuid().toString());
    }
} 
