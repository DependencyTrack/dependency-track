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

import java.util.Map;
import java.util.UUID;

import org.dependencytrack.PersistenceCapableTest;
import org.junit.Assert;
import org.junit.Test;

public class OutdatedComponentFindingTest extends PersistenceCapableTest {

    private UUID projectUuid = UUID.randomUUID();
    private OutdatedComponentFinding finding = new OutdatedComponentFinding(projectUuid, "component-uuid", "component-name", "component-group",
            "component-version", "component-purl", "component-cpe", "latestVersion", "lastChecked", "published");

    @Test
    public void testComponent() {
        Map map = finding.getComponent();
        Assert.assertEquals("component-uuid", map.get("uuid"));
        Assert.assertEquals("component-name", map.get("name"));
        Assert.assertEquals("component-group", map.get("group"));
        Assert.assertEquals("component-version", map.get("version"));
        Assert.assertEquals("component-purl", map.get("purl"));
        Assert.assertEquals("component-cpe", map.get("cpe"));
        Assert.assertNull("latestVersion", map.get("latestVersion"));
        Assert.assertNull("lastChecked", map.get("lastChecked"));
        Assert.assertNull("published", map.get("published"));
    }

}
