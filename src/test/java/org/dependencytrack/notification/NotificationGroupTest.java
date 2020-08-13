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
package org.dependencytrack.notification;

import org.junit.Assert;
import org.junit.Test;

public class NotificationGroupTest {

    @Test
    public void testEnums() {
        // System Groups
        Assert.assertEquals("CONFIGURATION", NotificationGroup.CONFIGURATION.name());
        Assert.assertEquals("DATASOURCE_MIRRORING", NotificationGroup.DATASOURCE_MIRRORING.name());
        Assert.assertEquals("REPOSITORY", NotificationGroup.REPOSITORY.name());
        Assert.assertEquals("ANALYZER", NotificationGroup.ANALYZER.name());
        Assert.assertEquals("INTEGRATION", NotificationGroup.INTEGRATION.name());
        Assert.assertEquals("INDEXING_SERVICE", NotificationGroup.INDEXING_SERVICE.name());
        // Portfolio Groups
        Assert.assertEquals("NEW_VULNERABILITY", NotificationGroup.NEW_VULNERABILITY.name());
        Assert.assertEquals("NEW_VULNERABLE_DEPENDENCY", NotificationGroup.NEW_VULNERABLE_DEPENDENCY.name());
        //Assert.assertEquals("NEW_OUTDATED_COMPONENT", NotificationGroup.NEW_OUTDATED_COMPONENT.name());
        //Assert.assertEquals("FIXED_VULNERABILITY", NotificationGroup.FIXED_VULNERABILITY.name());
        //Assert.assertEquals("FIXED_OUTDATED", NotificationGroup.FIXED_OUTDATED.name());
        //Assert.assertEquals("GLOBAL_AUDIT_CHANGE", NotificationGroup.GLOBAL_AUDIT_CHANGE.name());
        Assert.assertEquals("PROJECT_AUDIT_CHANGE", NotificationGroup.PROJECT_AUDIT_CHANGE.name());
    }
}
