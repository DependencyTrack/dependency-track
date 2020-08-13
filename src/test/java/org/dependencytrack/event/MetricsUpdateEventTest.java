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
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.junit.Assert;
import org.junit.Test;

public class MetricsUpdateEventTest {

    @Test
    public void testPortfolioEvent() {
        // This type of event should never occur, but in case it does, default to portfolio event
        Component component = null;
        MetricsUpdateEvent event = new MetricsUpdateEvent(component);
        Assert.assertNull(event.getTarget());
        Assert.assertEquals(MetricsUpdateEvent.Type.PORTFOLIO, event.getType());
    }

    @Test
    public void testPortfolioTypeEvent() {
        MetricsUpdateEvent event = new MetricsUpdateEvent(MetricsUpdateEvent.Type.PORTFOLIO);
        Assert.assertNull(event.getTarget());
        Assert.assertEquals(MetricsUpdateEvent.Type.PORTFOLIO, event.getType());
    }

    @Test
    public void testProjectEvent() {
        Project project = new Project();
        MetricsUpdateEvent event = new MetricsUpdateEvent(project);
        Assert.assertEquals(project, event.getTarget());
        Assert.assertEquals(MetricsUpdateEvent.Type.PROJECT, event.getType());
    }

    @Test
    public void testComponentEvent() {
        Component component = new Component();
        MetricsUpdateEvent event = new MetricsUpdateEvent(component);
        Assert.assertEquals(component, event.getTarget());
        Assert.assertEquals(MetricsUpdateEvent.Type.COMPONENT, event.getType());
    }

    @Test
    public void testVulnerabilityEvent() {
        // This is actually not a supported use case and will therefore default to PORTFOLIO event
        Vulnerability vulnerability = new Vulnerability();
        MetricsUpdateEvent event = new MetricsUpdateEvent(vulnerability);
        Assert.assertEquals(vulnerability, event.getTarget());
        Assert.assertEquals(MetricsUpdateEvent.Type.PORTFOLIO, event.getType());
    }

    @Test
    public void testVulnerabilityTypeEvent() {
        MetricsUpdateEvent event = new MetricsUpdateEvent(MetricsUpdateEvent.Type.VULNERABILITY);
        Assert.assertNull(event.getTarget());
        Assert.assertEquals(MetricsUpdateEvent.Type.VULNERABILITY, event.getType());
    }
}
