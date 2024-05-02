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

import alpine.server.json.TrimmedStringDeserializer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import java.time.ZonedDateTime;

/**
 * Defines a Model class for scheduled notification configurations.
 *
 * @author Max Schiller
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScheduledNotificationRule extends NotificationRule {
    @Persistent(defaultFetchGroup = "true")
    @Column(name = "CRON_CONFIG", allowsNull = "true") // new column, must allow nulls on existing databases
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    // @Pattern(regexp = RegexSequence.Definition.CRON, message = "The message may only contain characters valid in cron strings")
    private String cronConfig;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "LAST_EXECUTION_TIME", allowsNull = "true") // new column, must allow nulls on existing databases
    private ZonedDateTime lastExecutionTime;

    @Persistent
    @Column(name = "PUBLISH_ONLY_WITH_UPDATES", allowsNull = "true") // new column, must allow nulls on existing databases
    private boolean publishOnlyWithUpdates;

    public String getCronConfig() {
        var cronConfig = ConfigPropertyConstants.NOTIFICATION_CRON_DEFAULT_INTERVAL.getDefaultPropertyValue();
        if (this.cronConfig != null) {
            cronConfig = this.cronConfig;
        }
        return cronConfig;
    }

    public void setCronConfig(String cronConfig) {
        if (cronConfig == null) {
            this.cronConfig = ConfigPropertyConstants.NOTIFICATION_CRON_DEFAULT_INTERVAL.getDefaultPropertyValue();
            return;
        }
        this.cronConfig = cronConfig;
    }

    public ZonedDateTime getLastExecutionTime() {
        if (lastExecutionTime == null) {
            return ZonedDateTime.now();
        }
        return lastExecutionTime;
    }

    public void setLastExecutionTime(ZonedDateTime lastExecutionTime) {
        this.lastExecutionTime = lastExecutionTime;
    }

    public boolean getPublishOnlyWithUpdates() {
        return publishOnlyWithUpdates;
    }

    public void setPublishOnlyWithUpdates(boolean publishOnlyWithUpdates) {
        this.publishOnlyWithUpdates = publishOnlyWithUpdates;
    }
}