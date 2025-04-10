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

import org.dependencytrack.model.NotificationTriggerType;

public enum NotificationGroup {

    // System Groups
    CONFIGURATION(NotificationTriggerType.EVENT),
    DATASOURCE_MIRRORING(NotificationTriggerType.EVENT),
    REPOSITORY(NotificationTriggerType.EVENT),
    INTEGRATION(NotificationTriggerType.EVENT),
    INDEXING_SERVICE(NotificationTriggerType.EVENT),
    FILE_SYSTEM(NotificationTriggerType.EVENT),
    ANALYZER(NotificationTriggerType.EVENT),

    // Portfolio Groups
    NEW_VULNERABILITY(NotificationTriggerType.EVENT),
    NEW_VULNERABILITIES_SUMMARY(NotificationTriggerType.SCHEDULE),
    NEW_VULNERABLE_DEPENDENCY(NotificationTriggerType.EVENT),
    //NEW_OUTDATED_COMPONENT,
    //FIXED_VULNERABILITY,
    //FIXED_OUTDATED,
    //GLOBAL_AUDIT_CHANGE,
    PROJECT_AUDIT_CHANGE(NotificationTriggerType.EVENT),
    BOM_CONSUMED(NotificationTriggerType.EVENT),
    BOM_PROCESSED(NotificationTriggerType.EVENT),
    BOM_PROCESSING_FAILED(NotificationTriggerType.EVENT),
    BOM_VALIDATION_FAILED(NotificationTriggerType.EVENT),
    VEX_CONSUMED(NotificationTriggerType.EVENT),
    VEX_PROCESSED(NotificationTriggerType.EVENT),
    POLICY_VIOLATION(NotificationTriggerType.EVENT),
    NEW_POLICY_VIOLATIONS_SUMMARY(NotificationTriggerType.SCHEDULE),
    PROJECT_CREATED(NotificationTriggerType.EVENT),
    USER_CREATED(NotificationTriggerType.EVENT),
    USER_DELETED(NotificationTriggerType.EVENT);

    private final NotificationTriggerType supportedTriggerType;

    NotificationGroup(final NotificationTriggerType supportedTriggerType) {
        this.supportedTriggerType = supportedTriggerType;
    }

    public NotificationTriggerType getSupportedTriggerType() {
        return supportedTriggerType;
    }

}
