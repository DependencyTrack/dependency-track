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

import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.NotificationTriggerType;
import org.dependencytrack.persistence.jdbi.mapping.OptionalColumnRowMapper;
import org.jdbi.v3.core.generic.GenericType;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Set;
import java.util.UUID;

/**
 * @since 5.0.0
 */
final class NotificationRuleRowMapper implements OptionalColumnRowMapper<NotificationRule> {

    private static final GenericType<Set<NotificationGroup>> GROUPS_TYPE = new GenericType<>() {};

    @Override
    public NotificationRule map(ResultSet rs, StatementContext ctx, Columns columns) throws SQLException {
        final ColumnMapper<Set<NotificationGroup>> groupsColumnMapper =
                ctx.findColumnMapperFor(GROUPS_TYPE).orElseThrow();

        final var rule = new NotificationRule();
        columns.maybeSet(rs, "ID", ResultSet::getLong, rule::setId);
        columns.maybeSet(rs, "UUID", (r, columnName) -> r.getObject(columnName, UUID.class), rule::setUuid);
        columns.maybeSet(rs, "NAME", ResultSet::getString, rule::setName);
        columns.maybeSet(rs, "SCOPE", ResultSet::getString, v -> rule.setScope(NotificationScope.valueOf(v)));
        rule.setNotifyOn(groupsColumnMapper.map(rs, "NOTIFY_ON", ctx));
        columns.maybeSet(rs, "NOTIFY_CHILDREN", ResultSet::getBoolean, rule::setNotifyChildren);
        columns.maybeSet(
                rs, "TRIGGER_TYPE", ResultSet::getString, v -> rule.setTriggerType(NotificationTriggerType.valueOf(v)));
        columns.maybeSet(rs, "SCHEDULE_CRON", ResultSet::getString, rule::setScheduleCron);
        columns.maybeSet(rs, "SCHEDULE_LAST_TRIGGERED_AT", ResultSet::getTimestamp, rule::setScheduleLastTriggeredAt);
        columns.maybeSet(rs, "SCHEDULE_SKIP_UNCHANGED", ResultSet::getBoolean, rule::setScheduleSkipUnchanged);
        columns.maybeSet(rs, "FILTER_EXPRESSION", ResultSet::getString, rule::setFilterExpression);
        return rule;
    }
}
