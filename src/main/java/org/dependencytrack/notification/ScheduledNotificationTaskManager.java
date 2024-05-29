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

import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.dependencytrack.tasks.ActionOnDoneFutureTask;
import org.dependencytrack.tasks.SendScheduledNotificationTask;

import com.asahaf.javacron.Schedule;

public final class ScheduledNotificationTaskManager {
    private static final HashMap<UUID, ScheduledFuture<?>> SCHEDULED_NOTIFY_TASKS = new HashMap<UUID, ScheduledFuture<?>>();

    public static void scheduleNextRuleTask(UUID ruleUuid, Schedule schedule, long customDelay, TimeUnit delayUnit) {
        scheduleNextRuleTask(ruleUuid, schedule, customDelay, delayUnit, () -> scheduleNextRuleTask(ruleUuid, schedule));
    }

    public static void scheduleNextRuleTask(UUID ruleUuid, Schedule schedule) {
        scheduleNextRuleTask(ruleUuid, schedule, schedule.nextDuration(TimeUnit.MILLISECONDS), TimeUnit.MILLISECONDS);
    }

    public static void scheduleNextRuleTaskOnce(UUID ruleUuid, long customDelay, TimeUnit delayUnit){
        scheduleNextRuleTask(ruleUuid, null, customDelay, delayUnit, () -> cancelActiveRuleTask(ruleUuid));
    }

    private static void scheduleNextRuleTask(UUID ruleUuid, Schedule schedule, long customDelay, TimeUnit delayUnit, Runnable actionAfterTaskCompletion){
        var scheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        var futureTask = new ActionOnDoneFutureTask(new SendScheduledNotificationTask(ruleUuid), actionAfterTaskCompletion);

        var future = scheduledExecutor.schedule(
                futureTask,
                customDelay,
                TimeUnit.MILLISECONDS);
        SCHEDULED_NOTIFY_TASKS.put(ruleUuid, future);
    }

    public static void cancelActiveRuleTask(UUID ruleUuid) {
        if (SCHEDULED_NOTIFY_TASKS.containsKey(ruleUuid)) {
            SCHEDULED_NOTIFY_TASKS.get(ruleUuid).cancel(true);
            SCHEDULED_NOTIFY_TASKS.remove(ruleUuid);
        }
    }

    public static void cancelAllActiveRuleTasks(){
        for (var future : SCHEDULED_NOTIFY_TASKS.values()) {
            future.cancel(true);
        }
        SCHEDULED_NOTIFY_TASKS.clear();
    }
}
