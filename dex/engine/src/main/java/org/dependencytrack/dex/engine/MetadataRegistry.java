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
package org.dependencytrack.dex.engine;

import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.payload.PayloadConverter;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

final class MetadataRegistry {

    private static final Pattern WORKFLOW_NAME_PATTERN = Pattern.compile("^[\\w-]+");
    private static final Pattern ACTIVITY_NAME_PATTERN = WORKFLOW_NAME_PATTERN;

    @SuppressWarnings("rawtypes")
    private final Map<Class<? extends Workflow>, String> workflowNameByExecutorClass = new ConcurrentHashMap<>();

    @SuppressWarnings("rawtypes")
    private final Map<String, WorkflowMetadata> workflowMetadataByName = new HashMap<>();

    @SuppressWarnings("rawtypes")
    private final Map<Class<? extends Activity>, String> activityNameByExecutorClass = new ConcurrentHashMap<>();

    @SuppressWarnings("rawtypes")
    private final Map<String, ActivityMetadata> activityMetadataByName = new HashMap<>();

    <A, R> void registerWorkflow(
            Workflow<A, R> workflow,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout) {
        requireNonNull(workflow, "workflow must not be null");

        final WorkflowSpec workflowSpec = requireWorkflowSpec(workflow.getClass());

        registerWorkflow(
                workflowSpec.name(),
                workflowSpec.version(),
                argumentConverter,
                resultConverter,
                workflowSpec.defaultTaskQueue(),
                lockTimeout,
                workflow);
    }

    <A, R> void registerWorkflow(
            String name,
            int version,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            String defaultTaskQueueName,
            Duration lockTimeout,
            Workflow<A, R> workflow) {
        requireValidWorkflowName(name);
        requireValidWorkflowVersion(version);
        requireNonNull(argumentConverter, "argumentConverter must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");
        requireValidTaskQueueName(defaultTaskQueueName);
        requireValidLockTimeout(lockTimeout);
        requireNonNull(workflow, "workflow must not be null");

        if (workflowNameByExecutorClass.containsKey(workflow.getClass())) {
            throw new IllegalArgumentException(
                    "A workflow with workflow %s is already registered".formatted(
                            workflow.getClass().getName()));
        }
        if (workflowMetadataByName.containsKey(name)) {
            throw new IllegalArgumentException(
                    "A workflow with name %s is already registered".formatted(name));
        }

        final var metadata = new WorkflowMetadata<>(
                name,
                version,
                workflow,
                argumentConverter,
                resultConverter,
                defaultTaskQueueName,
                lockTimeout);
        workflowNameByExecutorClass.put(workflow.getClass(), name);
        workflowMetadataByName.put(name, metadata);
    }

    <A, R> void registerActivity(
            Activity<A, R> activity,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout) {
        requireNonNull(activity, "activity must not be null");

        final ActivitySpec activitySpec = requireActivitySpec(activity.getClass());

        registerActivity(
                activitySpec.name(),
                argumentConverter,
                resultConverter,
                activitySpec.defaultTaskQueue(),
                lockTimeout,
                activity);
    }

    <A, R> void registerActivity(
            String name,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            String defaultTaskQueueName,
            Duration lockTimeout,
            Activity<A, R> activity) {
        requireValidActivityName(name);
        requireNonNull(argumentConverter, "argumentConverter must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");
        requireValidTaskQueueName(defaultTaskQueueName);
        requireValidLockTimeout(lockTimeout);
        requireNonNull(activity, "activity must not be null");

        if (activityNameByExecutorClass.containsKey(activity.getClass())) {
            throw new IllegalArgumentException(
                    "An activity with activity %s is already registered".formatted(
                            activity.getClass().getName()));
        }
        if (activityMetadataByName.containsKey(name)) {
            throw new IllegalArgumentException(
                    "An activity with name %s is already registered".formatted(name));
        }

        final var metadata = new ActivityMetadata<>(
                name,
                activity,
                argumentConverter,
                resultConverter,
                defaultTaskQueueName,
                lockTimeout);
        activityNameByExecutorClass.put(activity.getClass(), name);
        activityMetadataByName.put(name, metadata);
    }

    @SuppressWarnings("rawtypes")
    List<WorkflowMetadata> getAllWorkflowMetadata() {
        return List.copyOf(workflowMetadataByName.values());
    }

    @SuppressWarnings("unchecked")
    <A, R> WorkflowMetadata<A, R> getWorkflowMetadata(Class<? extends Workflow<A, R>> workflowClass) {
        requireNonNull(workflowClass, "workflowClass must not be null");

        final String workflowName = getWorkflowName(workflowClass);

        return (WorkflowMetadata<A, R>) getWorkflowMetadata(workflowName);
    }

    @SuppressWarnings("rawtypes")
    WorkflowMetadata getWorkflowMetadata(String workflowName) {
        requireNonNull(workflowName, "workflowName must not be null");

        final WorkflowMetadata metadata = workflowMetadataByName.get(workflowName);
        if (metadata == null) {
            throw new NoSuchElementException("No workflow with name %s found".formatted(workflowName));
        }

        return metadata;
    }

    @SuppressWarnings("rawtypes")
    List<ActivityMetadata> getAllActivityMetadata() {
        return List.copyOf(activityMetadataByName.values());
    }

    @SuppressWarnings("unchecked")
    <A, R> ActivityMetadata<A, R> getActivityMetadata(Class<? extends Activity<A, R>> activityClass) {
        requireNonNull(activityClass, "activityClass must not be null");

        final String activityName = getActivityName(activityClass);

        return (ActivityMetadata<A, R>) getActivityMetadata(activityName);
    }

    @SuppressWarnings("rawtypes")
    ActivityMetadata getActivityMetadata(String activityName) {
        requireNonNull(activityName, "activityName must not be null");

        final ActivityMetadata metadata = activityMetadataByName.get(activityName);
        if (metadata == null) {
            throw new NoSuchElementException("No activity with name %s found".formatted(activityName));
        }

        return metadata;
    }

    @SuppressWarnings("rawtypes")
    private String getWorkflowName(Class<? extends Workflow> workflowClass) {
        return workflowNameByExecutorClass.computeIfAbsent(workflowClass, clazz -> requireWorkflowSpec(clazz).name());
    }

    @SuppressWarnings("rawtypes")
    private String getActivityName(Class<? extends Activity> activityClass) {
        return activityNameByExecutorClass.computeIfAbsent(activityClass, clazz -> requireActivitySpec(clazz).name());
    }

    @SuppressWarnings("rawtypes")
    private static ActivitySpec requireActivitySpec(Class<? extends Activity> activityClass) {
        final ActivitySpec spec = activityClass.getAnnotation(ActivitySpec.class);
        if (spec == null) {
            throw new IllegalArgumentException("Activity class must be annotated with @" + ActivitySpec.class.getSimpleName());
        }

        return spec;
    }

    @SuppressWarnings("rawtypes")
    private static WorkflowSpec requireWorkflowSpec(Class<? extends Workflow> activityClass) {
        final WorkflowSpec spec = activityClass.getAnnotation(WorkflowSpec.class);
        if (spec == null) {
            throw new IllegalArgumentException("Workflow class must be annotated with @" + WorkflowSpec.class.getSimpleName());
        }

        return spec;
    }

    private static void requireValidWorkflowName(String workflowName) {
        if (!WORKFLOW_NAME_PATTERN.matcher(workflowName).matches()) {
            throw new IllegalArgumentException("workflowName must match " + WORKFLOW_NAME_PATTERN.pattern());
        }
    }

    private static void requireValidWorkflowVersion(int workflowVersion) {
        if (workflowVersion < 1 || workflowVersion > 100) {
            throw new IllegalArgumentException("workflowVersion must be between 1 and 100, but is " + workflowVersion);
        }
    }

    private static void requireValidActivityName(String activityName) {
        if (!ACTIVITY_NAME_PATTERN.matcher(activityName).matches()) {
            throw new IllegalArgumentException("activityName must match " + ACTIVITY_NAME_PATTERN.pattern());
        }
    }

    private static void requireValidTaskQueueName(@Nullable String taskQueueName) {
        if (taskQueueName == null || taskQueueName.isBlank()) {
            throw new IllegalArgumentException("taskQueueName must not be null or blank");
        }
    }

    private static void requireValidLockTimeout(Duration lockTimeout) {
        requireNonNull(lockTimeout, "lockTimeout must not be null");
        if (!lockTimeout.isPositive()) {
            throw new IllegalArgumentException("lockTimeout must positive");
        }
    }

}
