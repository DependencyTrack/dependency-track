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
package org.dependencytrack.persistence.jdbi.mapping;

import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.NotificationTriggerType;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.ColumnMappers;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Set;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;
import static org.jdbi.v3.core.generic.GenericTypes.parameterizeClass;

/**
 * @since 5.0.0
 */
public final class NotificationRuleRowMapper implements RowMapper<NotificationRule> {

    private ColumnMapper<Set<NotificationGroup>> groupsColumnMapper;

    @Override
    @SuppressWarnings("unchecked")
    public void init(ConfigRegistry registry) {
        groupsColumnMapper = (ColumnMapper<Set<NotificationGroup>>) registry
                .get(ColumnMappers.class)
                .findFor(parameterizeClass(Set.class, NotificationGroup.class))
                .orElseThrow();
    }

    @Override
    public NotificationRule map(ResultSet rs, StatementContext ctx) throws SQLException {
        final var rule = new NotificationRule();
        maybeSet(rs, "ID", ResultSet::getLong, rule::setId);
        maybeSet(rs, "UUID", (r, columnName) -> r.getObject(columnName, UUID.class), rule::setUuid);
        maybeSet(rs, "NAME", ResultSet::getString, rule::setName);
        maybeSet(rs, "SCOPE", ResultSet::getString, v -> rule.setScope(NotificationScope.valueOf(v)));
        rule.setNotifyOn(groupsColumnMapper.map(rs, "NOTIFY_ON", ctx));
        maybeSet(rs, "NOTIFY_CHILDREN", ResultSet::getBoolean, rule::setNotifyChildren);
        maybeSet(rs, "TRIGGER_TYPE", ResultSet::getString, v -> rule.setTriggerType(NotificationTriggerType.valueOf(v)));
        maybeSet(rs, "SCHEDULE_CRON", ResultSet::getString, rule::setScheduleCron);
        maybeSet(rs, "SCHEDULE_LAST_TRIGGERED_AT", ResultSet::getTimestamp, rule::setScheduleLastTriggeredAt);
        maybeSet(rs, "SCHEDULE_SKIP_UNCHANGED", ResultSet::getBoolean, rule::setScheduleSkipUnchanged);
        maybeSet(rs, "FILTER_EXPRESSION", ResultSet::getString, rule::setFilterExpression);
        return rule;
    }

}