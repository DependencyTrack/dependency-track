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

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.dependencytrack.tasks.ActionOnDoneFutureTask;
import org.dependencytrack.tasks.SendScheduledNotificationTask;

import com.asahaf.javacron.Schedule;

import alpine.common.logging.Logger;

public final class ScheduledNotificationTaskManager {
    private static final Logger LOGGER = Logger.getLogger(ScheduledNotificationTaskManager.class);
    private static final HashMap<UUID, ScheduledFuture<?>> SCHEDULED_NOTIFY_TASKS = new HashMap<UUID, ScheduledFuture<?>>();

    public static void scheduleNextRuleTask(UUID ruleUuid, Schedule schedule) {
        var scheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        var futureTask = new ActionOnDoneFutureTask(new SendScheduledNotificationTask(ruleUuid), () -> scheduleNextRuleTask(ruleUuid, schedule));

        var future = scheduledExecutor.schedule(
                futureTask,
                schedule.nextDuration(TimeUnit.MILLISECONDS),
                TimeUnit.MILLISECONDS);
        SCHEDULED_NOTIFY_TASKS.put(ruleUuid, future);

        LOGGER.info(">>>>>>>>>> Scheduled notification task for rule " + ruleUuid + " @ " + LocalDateTime
                .ofInstant(Instant.ofEpochMilli(schedule.nextDuration(TimeUnit.MILLISECONDS)), ZoneId.systemDefault())
                .truncatedTo(ChronoUnit.SECONDS) + " >>>>>>>>>>");
    }

    public static void cancelActiveRuleTask(UUID ruleUuid) {
        if (SCHEDULED_NOTIFY_TASKS.containsKey(ruleUuid)) {
            SCHEDULED_NOTIFY_TASKS.get(ruleUuid).cancel(true);
            SCHEDULED_NOTIFY_TASKS.remove(ruleUuid);
            LOGGER.info("<<<<<<<<<< Canceled scheduled notification task for rule " + ruleUuid + " <<<<<<<<<<<<");
        }
    }

    public static void cancelAllActiveRuleTasks(){
        for (var future : SCHEDULED_NOTIFY_TASKS.values()) {
            future.cancel(true);
        }
        SCHEDULED_NOTIFY_TASKS.clear();
    }
}
