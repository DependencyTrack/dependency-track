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

import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.persistence.QueryManager;

import java.util.Set;

/**
 * @since 5.0.0
 */
public final class NotificationTestUtil {

    private NotificationTestUtil() {
    }

    public static NotificationRule createCatchAllNotificationRule(
            QueryManager qm,
            NotificationScope scope) {
        return qm.callInTransaction(() -> {
            final NotificationPublisher publisher = qm.createNotificationPublisher(
                    "catchAllPublisher",
                    "description",
                    "extensionName",
                    "templateContent",
                    "templateMimeType",
                    /* isDefault */ false);

            final NotificationRule rule = qm.createNotificationRule(
                    "catchAll",
                    scope,
                    NotificationLevel.INFORMATIONAL,
                    publisher);
            rule.setNotifyOn(Set.of(NotificationGroup.values()));

            return rule;
        });
    }

}
