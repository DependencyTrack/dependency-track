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
package org.dependencytrack.model;

import alpine.common.validation.RegexSequence;
import alpine.model.Team;
import alpine.notification.NotificationLevel;
import alpine.server.json.TrimmedStringDeserializer;
import com.asahaf.javacron.InvalidExpressionException;
import com.asahaf.javacron.Schedule;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.swagger.v3.oas.annotations.media.Schema;
import org.apache.commons.collections4.CollectionUtils;
import org.dependencytrack.model.validation.ValidCronExpression;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/**
 * Defines a Model class for notification configurations.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class NotificationRule implements Serializable {

    private static final long serialVersionUID = 2534439091019367263L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    /**
     * The String representation of the name of the notification.
     */
    @Persistent
    @Column(name = "NAME", allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    private String name;

    @Persistent
    @Column(name = "ENABLED")
    private boolean enabled;

    @Persistent
    @Column(name = "NOTIFY_CHILDREN", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private boolean notifyChildren;

    /**
     * In addition to warnings and errors, also emit a log message upon successful publishing.
     * <p>
     * Intended to aid in debugging of missing notifications, or environments where notification
     * delivery is critical and subject to auditing.
     *
     * @since 4.10.0
     */
    @Persistent
    @Column(name = "LOG_SUCCESSFUL_PUBLISH", allowsNull = "true")
    private boolean logSuccessfulPublish;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "SCOPE", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    private NotificationScope scope;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "NOTIFICATION_LEVEL", jdbcType = "VARCHAR")
    private NotificationLevel notificationLevel;

    @Persistent(table = "NOTIFICATIONRULE_PROJECTS", defaultFetchGroup = "true")
    @Join(column = "NOTIFICATIONRULE_ID")
    @Element(column = "PROJECT_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "name ASC, version ASC"))
    private List<Project> projects;

    @Persistent(table = "NOTIFICATIONRULE_TAGS", defaultFetchGroup = "true", mappedBy = "notificationRules")
    @Join(column = "NOTIFICATIONRULE_ID")
    @Element(column = "TAG_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "name ASC"))
    private List<Tag> tags;

    @Persistent(table = "NOTIFICATIONRULE_TEAMS", defaultFetchGroup = "true")
    @Join(column = "NOTIFICATIONRULE_ID")
    @Element(column = "TEAM_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "name ASC"))
    private List<Team> teams;

    @Persistent
    @Column(name = "NOTIFY_ON", length = 1024)
    private String notifyOn;

    @Persistent
    @Column(name = "MESSAGE", length = 1024)
    @Size(max = 1024)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The message may only contain printable characters")
    private String message;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PUBLISHER")
    private NotificationPublisher publisher;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PUBLISHER_CONFIG", jdbcType = "CLOB")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String publisherConfig;

    /**
     * @since 4.13.0
     */
    @Persistent
    @Column(name = "TRIGGER_TYPE", allowsNull = "false", defaultValue = "EVENT")
    @Schema(accessMode = Schema.AccessMode.READ_ONLY, requiredMode = Schema.RequiredMode.REQUIRED)
    private NotificationTriggerType triggerType;

    /**
     * @since 4.13.0
     */
    @Persistent
    @Column(name = "SCHEDULE_LAST_TRIGGERED_AT")
    @Schema(type = "integer", format = "int64", accessMode = Schema.AccessMode.READ_ONLY, description = "When the schedule last triggered, as UNIX epoch timestamp in milliseconds")
    private Date scheduleLastTriggeredAt;

    /**
     * @since 4.13.0
     */
    @Persistent
    @Column(name = "SCHEDULE_NEXT_TRIGGER_AT")
    @Schema(type = "integer", format = "int64", accessMode = Schema.AccessMode.READ_ONLY, description = "When the schedule triggers next, as UNIX epoch timestamp in milliseconds")
    private Date scheduleNextTriggerAt;

    /**
     * @since 4.13.0
     */
    @Persistent
    @Column(name = "SCHEDULE_CRON")
    @Schema(description = """
            Schedule of this rule as cron expression. \
            Must not be set for rules with trigger type EVENT.""")
    @ValidCronExpression
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String scheduleCron;

    /**
     * @since 4.13.0
     */
    @Persistent
    @Column(name = "SCHEDULE_SKIP_UNCHANGED")
    @Schema(description = """
            Whether to skip emitting a scheduled notification if it doesn't \
            contain any changes since its last emission. \
            Must not be set for rules with trigger type EVENT.""")
    private Boolean scheduleSkipUnchanged;

    @Persistent(defaultFetchGroup = "true", customValueStrategy = "uuid")
    @Unique(name = "NOTIFICATIONRULE_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    @NotNull
    public String getName() {
        return name;
    }

    public void setName(@NotNull String name) {
        this.name = name;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isNotifyChildren() {
        return notifyChildren;
    }

    public void setNotifyChildren(boolean notifyChildren) {
        this.notifyChildren = notifyChildren;
    }

    public boolean isLogSuccessfulPublish() {
        return logSuccessfulPublish;
    }

    public void setLogSuccessfulPublish(final boolean logSuccessfulPublish) {
        this.logSuccessfulPublish = logSuccessfulPublish;
    }

    @NotNull
    public NotificationScope getScope() {
        return scope;
    }

    public void setScope(@NotNull NotificationScope scope) {
        this.scope = scope;
    }

    public NotificationLevel getNotificationLevel() {
        return notificationLevel;
    }

    public void setNotificationLevel(NotificationLevel notificationLevel) {
        this.notificationLevel = notificationLevel;
    }

    public List<Project> getProjects() {
        return projects;
    }

    public void setProjects(List<Project> projects) {
        this.projects = projects;
    }

    public List<Tag> getTags() {
        return tags;
    }

    public void setTags(final List<Tag> tags) {
        this.tags = tags;
    }

    public List<Team> getTeams() {
        return teams;
    }

    public void setTeams(List<Team> teams) {
        this.teams = teams;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Set<NotificationGroup> getNotifyOn() {
        Set<NotificationGroup> result = new TreeSet<>();
        if (notifyOn != null) {
            String[] groups = notifyOn.split(",");
            for (String s: groups) {
                result.add(NotificationGroup.valueOf(s.trim()));
            }
        }
        return result;
    }

    public void setNotifyOn(Set<NotificationGroup> groups) {
        if (CollectionUtils.isEmpty(groups)) {
            this.notifyOn = null;
            return;
        }
        StringBuilder sb = new StringBuilder();
        List<NotificationGroup> list = new ArrayList<>(groups);
        Collections.sort(list);
        for (int i=0; i<list.size(); i++) {
            sb.append(list.get(i));
            if (i+1 < list.size()) {
                sb.append(",");
            }
        }
        this.notifyOn = sb.toString();
    }

    public NotificationPublisher getPublisher() {
        return publisher;
    }

    public void setPublisher(NotificationPublisher publisher) {
        this.publisher = publisher;
    }

    public String getPublisherConfig() {
        return publisherConfig;
    }

    public void setPublisherConfig(String publisherConfig) {
        this.publisherConfig = publisherConfig;
    }

    public NotificationTriggerType getTriggerType() {
        return triggerType;
    }

    public void setTriggerType(final NotificationTriggerType triggerType) {
        if (this.triggerType != null && this.triggerType != triggerType) {
            throw new IllegalStateException("Trigger type can not be changed");
        }
        this.triggerType = triggerType;
    }

    public Date getScheduleLastTriggeredAt() {
        return scheduleLastTriggeredAt;
    }

    public void setScheduleLastTriggeredAt(final Date scheduleLastTriggeredAt) {
        requireTriggerType(
                NotificationTriggerType.SCHEDULE,
                "scheduleLastTriggeredAt can not be set for rule with trigger type " + this.triggerType);
        this.scheduleLastTriggeredAt = scheduleLastTriggeredAt;
    }

    public Date getScheduleNextTriggerAt() {
        return scheduleNextTriggerAt;
    }

    public void setScheduleNextTriggerAt(final Date scheduleNextTriggerAt) {
        requireTriggerType(
                NotificationTriggerType.SCHEDULE,
                "scheduleNextTriggerAt can not be set for rule with trigger type " + this.triggerType);
        this.scheduleNextTriggerAt = scheduleNextTriggerAt;
    }

    public void updateScheduleNextTriggerAt() {
        requireTriggerType(
                NotificationTriggerType.SCHEDULE,
                "scheduleNextTriggerAt can not be set for rule with trigger type " + this.triggerType);
        requireNonNull(this.scheduleCron, "scheduleCron must not be null");
        requireNonNull(this.scheduleLastTriggeredAt, "scheduleLastTriggeredAt must not be null");

        try {
            final var schedule = Schedule.create(this.scheduleCron);
            this.scheduleNextTriggerAt = schedule.next(this.scheduleLastTriggeredAt);
        } catch (InvalidExpressionException e) {
            throw new IllegalStateException(e);
        }
    }

    public String getScheduleCron() {
        return scheduleCron;
    }

    public void setScheduleCron(final String scheduleCron) {
        requireTriggerType(
                NotificationTriggerType.SCHEDULE,
                "scheduleCron can not be set for rule with trigger type " + this.triggerType);
        this.scheduleCron = scheduleCron;
    }

    public Boolean isScheduleSkipUnchanged() {
        return scheduleSkipUnchanged;
    }

    public void setScheduleSkipUnchanged(final Boolean scheduleSkipUnchanged) {
        requireTriggerType(
                NotificationTriggerType.SCHEDULE,
                "scheduleSkipUnchanged can not be set for rule with trigger type " + this.triggerType);
        this.scheduleSkipUnchanged = scheduleSkipUnchanged;
    }

    @NotNull
    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(@NotNull UUID uuid) {
        this.uuid = uuid;
    }

    private void requireTriggerType(final NotificationTriggerType triggerType, final String message) {
        if (this.triggerType != triggerType) {
            throw new IllegalStateException(message);
        }
    }

}
