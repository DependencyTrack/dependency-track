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
package org.dependencytrack.notification;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class NotificationGroupTest {

    @Test
    void testEnums() {
        // System Groups
        Assertions.assertEquals("CONFIGURATION", NotificationGroup.CONFIGURATION.name());
        Assertions.assertEquals("DATASOURCE_MIRRORING", NotificationGroup.DATASOURCE_MIRRORING.name());
        Assertions.assertEquals("REPOSITORY", NotificationGroup.REPOSITORY.name());
        Assertions.assertEquals("ANALYZER", NotificationGroup.ANALYZER.name());
        Assertions.assertEquals("INTEGRATION", NotificationGroup.INTEGRATION.name());
        Assertions.assertEquals("INDEXING_SERVICE", NotificationGroup.INDEXING_SERVICE.name());
        // Portfolio Groups
        Assertions.assertEquals("NEW_VULNERABILITY", NotificationGroup.NEW_VULNERABILITY.name());
        Assertions.assertEquals("NEW_VULNERABLE_DEPENDENCY", NotificationGroup.NEW_VULNERABLE_DEPENDENCY.name());
        //Assertions.assertEquals("NEW_OUTDATED_COMPONENT", NotificationGroup.NEW_OUTDATED_COMPONENT.name());
        //Assertions.assertEquals("FIXED_VULNERABILITY", NotificationGroup.FIXED_VULNERABILITY.name());
        //Assertions.assertEquals("FIXED_OUTDATED", NotificationGroup.FIXED_OUTDATED.name());
        //Assertions.assertEquals("GLOBAL_AUDIT_CHANGE", NotificationGroup.GLOBAL_AUDIT_CHANGE.name());
        Assertions.assertEquals("PROJECT_AUDIT_CHANGE", NotificationGroup.PROJECT_AUDIT_CHANGE.name());
    }
}
