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

import org.dependencytrack.notification.api.publishing.NotificationRuleContact;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;

import java.util.Set;
import java.util.function.Supplier;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.0.0
 */
final class NotificationRuleContactsSupplier implements Supplier<Set<NotificationRuleContact>> {

    private final String ruleName;

    NotificationRuleContactsSupplier(String ruleName) {
        this.ruleName = ruleName;
    }

    @Override
    public Set<NotificationRuleContact> get() {
        return withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT DISTINCT
                           "USERNAME"
                         , "EMAIL"
                      FROM "NOTIFICATIONRULE" AS r
                     INNER JOIN "NOTIFICATIONRULE_TEAMS" AS nrt
                        ON nrt."NOTIFICATIONRULE_ID" = r."ID"
                     INNER JOIN "TEAM" AS t
                        ON t."ID" = nrt."TEAM_ID"
                     INNER JOIN "USERS_TEAMS" AS ut
                        ON ut."TEAM_ID" = t."ID"
                     INNER JOIN "USER" AS u
                        ON u."ID" = ut."USER_ID"
                     WHERE r."NAME" = :ruleName
                    """);

            return query
                    .bind("ruleName", ruleName)
                    .map(ConstructorMapper.of(NotificationRuleContact.class))
                    .set();
        });
    }
}
