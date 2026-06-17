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
package org.dependencytrack.dex.engine.api;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.payload.PayloadConverter;
import org.dependencytrack.dex.engine.api.event.DexEngineEvent;
import org.dependencytrack.dex.engine.api.event.DexEngineEventListener;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ExistsWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ListTaskQueuesRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunHistoryRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.engine.api.request.UpdateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.response.CreateWorkflowRunResponse;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.jspecify.annotations.Nullable;

import java.io.Closeable;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public interface DexEngine extends Closeable {

    void start();

    HealthCheckResponse probeHealth();

    /**
     * Register a workflow.
     * <p>
     * The executor's class <strong>must</strong> be annotated with {@link WorkflowSpec}.
     *
     * @param executor          The {@link Workflow} of the workflow.
     * @param argumentConverter The {@link PayloadConverter} to use for arguments.
     * @param resultConverter   The {@link PayloadConverter} to use for results.
     * @param lockTimeout       How long runs of this workflow shall be locked for execution.
     * @param <A>               Type of the workflow's argument.
     * @param <R>               Type of the workflow's result.
     * @throws IllegalStateException When the engine was already started.
     */
    <A, R> void registerWorkflow(
            Workflow<A, R> executor,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout);

    /**
     * Register an activity.
     * <p>
     * The executor's class <strong>must</strong> be annotated with {@link ActivitySpec}.
     *
     * @param executor          The {@link Activity} of the activity.
     * @param argumentConverter The {@link PayloadConverter} to use for arguments.
     * @param resultConverter   The {@link PayloadConverter} to use for results.
     * @param lockTimeout       How instances of this activity shall be locked for execution.
     * @param <A>               Type of the activity's argument.
     * @param <R>               Type of the activity's result.
     * @throws IllegalStateException When the engine was already started.
     */
    <A, R> void registerActivity(
            Activity<A, R> executor,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout);

    /**
     * Register a task worker.
     *
     * @param options Options of the worker.
     * @throws IllegalStateException When the engine was already started.
     */
    void registerTaskWorker(TaskWorkerOptions options);

    /**
     * Add a listener for {@link DexEngineEvent}s.
     *
     * @param listener The {@link DexEngineEventListener} to add
     * @throws IllegalStateException When the engine was already started.
     */
    void addEventListener(DexEngineEventListener<?> listener);

    /**
     * Create one or more workflow runs.
     * <p>
     * Responses may be correlated with requests using {@link CreateWorkflowRunRequest#requestId()}
     * and {@link CreateWorkflowRunResponse#requestId()}.
     *
     * @param requests Requests for runs to create.
     * @return IDs of the created runs.
     * @throws NoSuchElementException When a workflow is not known to the engine.
     */
    List<CreateWorkflowRunResponse> createRuns(Collection<? extends CreateWorkflowRunRequest<?>> requests);

    /**
     * Creates a single workflow run.
     * <p>
     * May return {@code null} when another run with the same instance ID is already in progress.
     *
     * @param request Request for the run to create.
     * @param <A>     Type of the workflow's argument.
     * @return ID of the created run.
     * @see #createRuns(Collection)
     */
    default <A> @Nullable UUID createRun(final CreateWorkflowRunRequest<A> request) {
        final List<CreateWorkflowRunResponse> responses = createRuns(List.of(request));
        if (responses.isEmpty()) {
            return null;
        }

        return responses.getFirst().runId();
    }

    /**
     * Retrieve all data about a workflow run, including its full event history.
     * <p>
     * If only high-level information about the run is required, prefer to use
     * {@link #getRunMetadataById(UUID)} as it is significantly more efficient.
     *
     * @param id ID of the workflow run.
     * @return The run data, or {@code null} if no run with the given ID exists.
     */
    @Nullable
    WorkflowRun getRunById(UUID id);

    /**
     * Retrieve metadata about a workflow run by ID.
     *
     * @param id ID of the workflow run.
     * @return The run metadata, or {@code null} if no run with the given ID exists.
     */
    @Nullable
    WorkflowRunMetadata getRunMetadataById(UUID id);

    /**
     * Retrieve metadata about a workflow run by workflow instance ID.
     *
     * @param instanceId Workflow instance ID of the workflow run.
     * @return Metadata of the matching run, <strong>if and only if</strong>
     * the run is in non-terminal state. Metadata of terminal runs is not returned.
     */
    @Nullable
    WorkflowRunMetadata getRunMetadataByInstanceId(String instanceId);

    Page<WorkflowRunMetadata> listRuns(ListWorkflowRunsRequest request);

    /**
     * Check whether at least one workflow run matching the given criteria exists.
     *
     * @param request Filter criteria for the lookup.
     * @return {@code true} when a matching run exists, {@code false} otherwise.
     */
    boolean existsRun(ExistsWorkflowRunRequest request);

    /**
     * Request the cancellation of a workflow run.
     * <p>
     * Note that the cancellation is not instantaneous.
     * It is possible that the corresponding workflow run completes execution before the cancellation can take effect.
     *
     * @param runId  ID of the workflow run to cancel.
     * @param reason Reason for why the run is being canceled.
     * @throws NoSuchElementException When no workflow run with the given ID exists.
     * @throws IllegalStateException  When the workflow run is already in a terminal state,
     *                                or a cancellation has already been requested.
     */
    void requestRunCancellation(UUID runId, String reason);

    /**
     * Request the suspension of a workflow run.
     * <p>
     * Note that the suspension is not instantaneous.
     * It is possible that the corresponding workflow run completes execution before the suspension can take effect.
     *
     * @param runId ID of the workflow run to suspend.
     * @throws NoSuchElementException When no workflow run with the given ID exists.
     * @throws IllegalStateException  When the workflow run is already in a suspended or terminal state,
     *                                or a suspension has already been requested.
     */
    void requestRunSuspension(UUID runId);

    /**
     * Request the resumption of a currently suspended workflow run.
     * <p>
     * Note that the resumption is not instantaneous.
     * It is possible that the corresponding workflow run completes execution before the suspension can take effect.
     *
     * @param runId ID of the workflow run to cancel.
     * @throws IllegalStateException When the workflow run is <em>not</em> in a suspended state,
     *                               already in a terminal state, or a resumption has already been requested.
     */
    void requestRunResumption(UUID runId);

    /**
     * Retrieve the event history of a workflow run.
     *
     * @param request The request.
     * @return A {@link Page} containing {@link WorkflowRunHistoryEntry} items.
     */
    Page<WorkflowRunHistoryEntry> listRunHistory(ListWorkflowRunHistoryRequest request);

    /**
     * Send an external event to a workflow run.
     *
     * @param externalEvent The {@link ExternalEvent} to send.
     * @return A {@link CompletableFuture} that will complete when the event was successfully
     * recorded in the recipient workflow run's message inbox.
     * @throws IllegalStateException When the engine is not running.
     */
    CompletableFuture<Void> sendExternalEvent(ExternalEvent externalEvent);

    /**
     * Create a task queue.
     *
     * @param request The request.
     * @return {@code true} when the queue was created, {@code false} otherwise.
     * If a queue with the same name already exists, it will not be updated
     * and this method will return {@code false}.
     */
    boolean createTaskQueue(CreateTaskQueueRequest request);

    /**
     * Update a task queue.
     *
     * @param request The request.
     * @return {@code true} when the queue was updated, {@code false} otherwise.
     * @throws NoSuchElementException When no queue with the given name exist.
     */
    boolean updateTaskQueue(UpdateTaskQueueRequest request);

    /**
     * List all task queues known to the engine.
     *
     * @param request The request.
     * @return A {@link Page} containing {@link TaskQueue}s.
     */
    Page<TaskQueue> listTaskQueues(ListTaskQueuesRequest request);

}
