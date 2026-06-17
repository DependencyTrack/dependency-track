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
package org.dependencytrack.dex.engine.persistence;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.dex.engine.WorkflowMessage;
import org.dependencytrack.dex.engine.WorkflowTask;
import org.dependencytrack.dex.engine.api.TaskQueue;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.ListTaskQueuesRequest;
import org.dependencytrack.dex.engine.api.request.UpdateTaskQueueRequest;
import org.dependencytrack.dex.engine.persistence.command.CreateWorkflowRunCommand;
import org.dependencytrack.dex.engine.persistence.command.CreateWorkflowRunHistoryEntryCommand;
import org.dependencytrack.dex.engine.persistence.command.DeleteWorkflowMessagesCommand;
import org.dependencytrack.dex.engine.persistence.command.PollWorkflowTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.UpdateAndUnlockRunCommand;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowEvent;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowEvents;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowTask;
import org.dependencytrack.dex.engine.persistence.request.GetWorkflowRunHistoryRequest;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper.TypedJsonMapper;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.SequencedCollection;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;
import static org.jdbi.v3.core.generic.GenericTypes.parameterizeClass;

public final class WorkflowDao extends AbstractDao {

    private static final int WORKFLOW_TASK_QUEUE_LOCK_NAMESPACE = 657204660;

    public WorkflowDao(Handle jdbiHandle) {
        super(jdbiHandle);
    }

    public boolean createWorkflowTaskQueue(CreateTaskQueueRequest request) {
        return jdbiHandle
                .createQuery("""
                        with lock as materialized (
                          select pg_advisory_xact_lock(:lockNamespace, :lockKey)
                        )
                        select dex_create_workflow_task_queue(:name, cast(:capacity as smallint))
                          from lock
                        """)
                .bindMethods(request)
                .bind("lockNamespace", WORKFLOW_TASK_QUEUE_LOCK_NAMESPACE)
                .bind("lockKey", request.name().hashCode())
                .mapTo(boolean.class)
                .one();
    }

    public boolean updateWorkflowTaskQueue(UpdateTaskQueueRequest request) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_queue as (
                  select name
                    from dex_workflow_task_queue
                   where name = :name
                ),
                cte_updated_queue as (
                  update dex_workflow_task_queue as queue
                     set status = coalesce(:status, queue.status)
                       , capacity = coalesce(:capacity, queue.capacity)
                       , updated_at = now()
                   where queue.name = :name
                     and (queue.status != :status or queue.capacity != :capacity)
                   returning 1
                )
                select exists(select 1 from cte_queue) as exists
                     , exists(select 1 from cte_updated_queue) as updated
                """);

        final Map.Entry<Boolean, Boolean> existsAndUpdated = query
                .bindMethods(request)
                .map((rs, ctx) -> Map.entry(rs.getBoolean(1), rs.getBoolean(2)))
                .one();

        final boolean exists = existsAndUpdated.getKey();
        final boolean updated = existsAndUpdated.getValue();

        if (!exists) {
            throw new NoSuchElementException();
        }

        return updated;
    }

    public boolean doesWorkflowTaskQueueExists(String name) {
        final Query query = jdbiHandle.createQuery("""
                select exists(
                  select 1
                    from dex_workflow_task_queue
                   where name = :name
                )
                """);

        return query
                .bind("name", name)
                .mapTo(boolean.class)
                .one();
    }

    record ListWorkflowTaskQueuesPageToken(String lastName) implements PageToken {
    }

    public Page<TaskQueue> listWorkflowTaskQueues(ListTaskQueuesRequest request) {
        requireNonNull(request, "request must not be null");

        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="lastName" type="boolean" -->
                select 'WORKFLOW' as type
                     , name
                     , status
                     , capacity
                     , (
                         select count(*)
                           from dex_workflow_task as task
                          where task.queue_name = queue.name
                       ) as depth
                     , created_at
                     , updated_at
                  from dex_workflow_task_queue as queue
                 where true
                <#if lastName>
                   and name > :lastName
                </#if>
                 order by name
                 limit :limit
                """);

        final var pageTokenValue = decodePageToken(request.pageToken(), ListWorkflowTaskQueuesPageToken.class);

        // Query for one additional row to determine if there are more results.
        final int limit = request.limit() > 0 ? request.limit() : 100;
        final int limitWithNext = limit + 1;

        final List<TaskQueue> rows = query
                .bind("limit", limitWithNext)
                .bind("lastName", pageTokenValue != null ? pageTokenValue.lastName() : null)
                .defineNamedBindings()
                .mapTo(TaskQueue.class)
                .list();

        final List<TaskQueue> resultItems = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListWorkflowTaskQueuesPageToken nextPageToken = rows.size() == limitWithNext
                ? new ListWorkflowTaskQueuesPageToken(resultItems.getLast().name())
                : null;

        return new Page<>(resultItems, encodePageToken(nextPageToken));
    }

    public Map<UUID, UUID> createRuns(Collection<CreateWorkflowRunCommand> commands) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_cmd as (
                  select *
                    from unnest (
                      :requestIds
                    , :ids
                    , :parentIds
                    , :workflowNames
                    , :workflowVersions
                    , :workflowInstanceIds
                    , :taskQueueNames
                    , :concurrencyKeys
                    , :priorities
                    , cast(:labelsJsons as jsonb[])
                    , :createdAts
                    ) as t (
                      request_id
                    , id
                    , parent_id
                    , workflow_name
                    , workflow_version
                    , workflow_instance_id
                    , task_queue_name
                    , concurrency_key
                    , priority
                    , labels
                    , created_at
                    )
                ),
                cte_created as (
                  insert into dex_workflow_run (
                    id
                  , parent_id
                  , workflow_name
                  , workflow_version
                  , workflow_instance_id
                  , task_queue_name
                  , concurrency_key
                  , priority
                  , labels
                  , created_at
                  )
                  select id
                       , parent_id
                       , workflow_name
                       , workflow_version
                       , workflow_instance_id
                       , task_queue_name
                       , concurrency_key
                       , priority
                       , labels
                       , created_at
                    from cte_cmd
                  -- Index expression of dex_workflow_run_workflow_instance_id_idx.
                  on conflict (workflow_instance_id)
                        where workflow_instance_id is not null
                          and status in ('CREATED', 'RUNNING', 'SUSPENDED')
                  do nothing
                  returning id
                )
                select cte_cmd.request_id as request_id
                     , cte_created.id as run_id
                  from cte_created
                 inner join cte_cmd
                    on cte_cmd.id = cte_created.id
                """);

        final var requestIds = new UUID[commands.size()];
        final var ids = new UUID[commands.size()];
        final var parentIds = new @Nullable UUID[commands.size()];
        final var workflowNames = new String[commands.size()];
        final var workflowVersions = new int[commands.size()];
        final var workflowInstanceIds = new @Nullable String[commands.size()];
        final var taskQueueNames = new String[commands.size()];
        final var concurrencyKeys = new @Nullable String[commands.size()];
        final var priorities = new int[commands.size()];
        final var labelsJsons = new @Nullable String[commands.size()];
        final var createdAts = new Instant[commands.size()];

        final TypedJsonMapper jsonMapper = jdbiHandle
                .getConfig(JsonConfig.class).getJsonMapper()
                .forType(parameterizeClass(Map.class, String.class, String.class), jdbiHandle.getConfig());

        int i = 0;
        for (final CreateWorkflowRunCommand command : commands) {
            final String labelsJson;
            if (command.labels() == null || command.labels().isEmpty()) {
                labelsJson = null;
            } else {
                labelsJson = jsonMapper.toJson(command.labels(), jdbiHandle.getConfig());
            }

            requestIds[i] = command.requestId();
            ids[i] = command.id();
            parentIds[i] = command.parentId();
            workflowNames[i] = command.workflowName();
            workflowVersions[i] = command.workflowVersion();
            workflowInstanceIds[i] = command.workflowInstanceId();
            taskQueueNames[i] = command.taskQueueName();
            concurrencyKeys[i] = command.concurrencyKey();
            priorities[i] = command.priority();
            labelsJsons[i] = labelsJson;
            createdAts[i] = command.createdAt();
            i++;
        }

        return query
                .bind("requestIds", requestIds)
                .bind("ids", ids)
                .bind("parentIds", parentIds)
                .bind("workflowNames", workflowNames)
                .bind("workflowVersions", workflowVersions)
                .bind("workflowInstanceIds", workflowInstanceIds)
                .bind("taskQueueNames", taskQueueNames)
                .bind("concurrencyKeys", concurrencyKeys)
                .bind("priorities", priorities)
                .bind("labelsJsons", labelsJsons)
                .bind("createdAts", createdAts)
                .map((rs, ctx) -> Map.entry(
                        rs.getObject("request_id", UUID.class),
                        rs.getObject("run_id", UUID.class)))
                .collectToMap(Map.Entry::getKey, Map.Entry::getValue);
    }

    public List<UUID> updateAndUnlockRuns(
            String engineInstanceId,
            Collection<UpdateAndUnlockRunCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                with
                cte_cmd as (
                  select *
                    from unnest (:ids, :queueNames, :statuses, :customStatuses, :continuedAsNews, :stickyTos, :updatedAts, :startedAts, :completedAts, :lockVersions)
                      as t(id, queue_name, status, custom_status, continued_as_new, sticky_to, updated_at, started_at, completed_at, lock_version)
                ),
                cte_deleted_task as (
                  delete
                    from dex_workflow_task as task
                   using cte_cmd
                   where task.queue_name = cte_cmd.queue_name
                     and task.workflow_run_id = cte_cmd.id
                     and task.locked_by = :engineInstanceId
                     and task.lock_version = cte_cmd.lock_version
                  returning task.workflow_run_id
                          , task.queue_name
                )
                update dex_workflow_run as run
                   set status = coalesce(cte_cmd.status, run.status)
                     , custom_status = coalesce(cte_cmd.custom_status, run.custom_status)
                     , continued_as_new_generation =
                         case
                           when cte_cmd.continued_as_new
                           then run.continued_as_new_generation + 1
                           else run.continued_as_new_generation
                         end
                     , sticky_to = cte_cmd.sticky_to
                     , sticky_until = case when cte_cmd.sticky_to is not null then now() + interval '30 seconds' end
                     , updated_at = coalesce(cte_cmd.updated_at, run.updated_at)
                     , started_at = coalesce(cte_cmd.started_at, run.started_at)
                     , completed_at = coalesce(cte_cmd.completed_at, run.completed_at)
                  from cte_deleted_task
                 inner join cte_cmd
                    on cte_cmd.id = cte_deleted_task.workflow_run_id
                 where run.id = cte_deleted_task.workflow_run_id
                returning run.id
                """);

        final var ids = new UUID[commands.size()];
        final var queueNames = new String[commands.size()];
        final var statuses = new WorkflowRunStatus[commands.size()];
        final var customStatuses = new @Nullable String[commands.size()];
        final var continuedAsNews = new boolean[commands.size()];
        final var stickyTos = new @Nullable String[commands.size()];
        final var updatedAts = new @Nullable Instant[commands.size()];
        final var startedAts = new @Nullable Instant[commands.size()];
        final var completedAts = new @Nullable Instant[commands.size()];
        final var lockVersions = new int[commands.size()];

        int i = 0;
        for (final UpdateAndUnlockRunCommand command : commands) {
            ids[i] = command.id();
            queueNames[i] = command.queueName();
            statuses[i] = command.status();
            customStatuses[i] = command.customStatus();
            continuedAsNews[i] = command.continuedAsNew();
            stickyTos[i] = (command.status() != null && !command.status().isTerminal())
                    ? engineInstanceId
                    : null;
            updatedAts[i] = command.updatedAt();
            startedAts[i] = command.startedAt();
            completedAts[i] = command.completedAt();
            lockVersions[i] = command.lockVersion();
            i++;
        }

        return update
                .bind("engineInstanceId", engineInstanceId)
                .bind("ids", ids)
                .bind("queueNames", queueNames)
                .bind("statuses", statuses)
                .bind("customStatuses", customStatuses)
                .bind("continuedAsNews", continuedAsNews)
                .bind("stickyTos", stickyTos)
                .bind("updatedAts", updatedAts)
                .bind("startedAts", startedAts)
                .bind("completedAts", completedAts)
                .bind("lockVersions", lockVersions)
                .executeAndReturnGeneratedKeys()
                .mapTo(UUID.class)
                .list();
    }

    public @Nullable WorkflowRunMetadata getRunMetadataById(UUID id) {
        final Query query = jdbiHandle.createQuery("""
                select *
                  from dex_workflow_run
                 where id = :id
                """);

        return query
                .bind("id", id)
                .mapTo(WorkflowRunMetadata.class)
                .findOne()
                .orElse(null);
    }

    public @Nullable WorkflowRunMetadata getRunMetadataByInstanceId(String instanceId) {
        final Query query = jdbiHandle.createQuery("""
                select *
                  from dex_workflow_run
                 where workflow_instance_id = :instanceId
                   and status in ('CREATED', 'RUNNING', 'SUSPENDED')
                """);

        return query
                .bind("instanceId", instanceId)
                .mapTo(WorkflowRunMetadata.class)
                .findOne()
                .orElse(null);
    }

    public Map<UUID, PolledWorkflowTask> pollAndLockWorkflowTasks(
            String engineInstanceId,
            String queueName,
            Collection<PollWorkflowTaskCommand> commands,
            int limit) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_poll_req as (
                  select *
                    from unnest(:workflowNames, :lockTimeouts)
                      as t(workflow_name, lock_timeout)
                ),
                cte_poll as (
                  select task.workflow_run_id
                       , cte_poll_req.lock_timeout
                    from dex_workflow_task as task
                   inner join dex_workflow_task_queue as queue
                      on queue.name = task.queue_name
                   inner join cte_poll_req
                      on cte_poll_req.workflow_name = task.workflow_name
                   where task.queue_name = :queueName
                     and queue.status = 'ACTIVE'
                     and (
                           task.sticky_to is null
                           or task.sticky_until < now()
                           or (task.sticky_to = :engineInstanceId and task.sticky_until >= now())
                         )
                     and (task.locked_until is null or task.locked_until <= now())
                   order by task.priority desc
                          , task.workflow_run_id
                     for no key update of task
                    skip locked
                   limit :limit
                ),
                cte_locked as (
                  update dex_workflow_task as task
                     set locked_by = :engineInstanceId
                       , locked_until = now() + cte_poll.lock_timeout
                       , lock_version = lock_version + 1
                   from cte_poll
                  where task.queue_name = :queueName
                    and task.workflow_run_id = cte_poll.workflow_run_id
                  returning task.queue_name
                          , task.workflow_run_id
                          , task.locked_until
                          , task.lock_version
                )
                select run.id
                     , run.workflow_name
                     , run.workflow_version
                     , run.workflow_instance_id
                     , run.task_queue_name
                     , run.concurrency_key
                     , run.priority
                     , run.labels
                     , run.continued_as_new_generation
                     , cte_locked.locked_until
                     , cte_locked.lock_version
                  from dex_workflow_run as run
                 inner join cte_locked
                    on cte_locked.queue_name = run.task_queue_name
                   and cte_locked.workflow_run_id = run.id
                """);

        final var workflowNames = new String[commands.size()];
        final var lockTimeouts = new Duration[commands.size()];

        int i = 0;
        for (final PollWorkflowTaskCommand command : commands) {
            workflowNames[i] = command.workflowName();
            lockTimeouts[i] = command.lockTimeout();
            i++;
        }

        return query
                .bind("engineInstanceId", engineInstanceId)
                .bind("queueName", queueName)
                .bind("workflowNames", workflowNames)
                .bind("lockTimeouts", lockTimeouts)
                .bind("limit", limit)
                .mapTo(PolledWorkflowTask.class)
                .collectToMap(PolledWorkflowTask::runId, Function.identity());
    }

    public int abandonWorkflowTasks(String engineInstanceId, Collection<WorkflowTask> tasks) {
        final Update update = jdbiHandle.createUpdate("""
                update dex_workflow_task as task
                   set locked_by = null
                     , locked_until = now() + interval '15 seconds'
                  from unnest(:queueNames, :runIds, :lockVersions)
                    as t(queue_name, run_id, lock_version)
                 where task.queue_name = t.queue_name
                   and task.workflow_run_id = t.run_id
                   and task.locked_by = :engineInstanceId
                   and task.lock_version = t.lock_version
                """);

        final var queueNames = new String[tasks.size()];
        final var runIds = new UUID[tasks.size()];
        final var lockVersions = new int[tasks.size()];

        int i = 0;
        for (final WorkflowTask task : tasks) {
            queueNames[i] = task.queueName();
            runIds[i] = task.workflowRunId();
            lockVersions[i] = task.lock().version();
            i++;
        }

        return update
                .bind("engineInstanceId", engineInstanceId)
                .bind("queueNames", queueNames)
                .bind("runIds", runIds)
                .bind("lockVersions", lockVersions)
                .execute();
    }

    public int createMessages(SequencedCollection<WorkflowMessage> messages) {
        final Update update = jdbiHandle.createUpdate("""
                insert into dex_workflow_inbox (
                  workflow_run_id
                , visible_from
                , event
                )
                select run_id
                     , coalesce(visible_from, now())
                     , event
                  from unnest(:runIds, :visibleFroms, :events)
                    as t(run_id, visible_from, event)
                """);

        final var runIds = new UUID[messages.size()];
        final var visibleFroms = new @Nullable Instant[messages.size()];
        final var events = new byte[messages.size()][];

        int i = 0;
        for (final WorkflowMessage message : messages) {
            runIds[i] = message.recipientRunId();
            visibleFroms[i] = message.visibleFrom();
            events[i] = message.event().toByteArray();
            i++;
        }

        return update
                .bind("runIds", runIds)
                .bind("visibleFroms", visibleFroms)
                .bind("events", events)
                .execute();
    }

    public Map<UUID, PolledWorkflowEvents> pollRunEvents(Collection<GetWorkflowRunHistoryRequest> requests) {
        final Query query = jdbiHandle.createQuery("""
                with
                cte_req as (
                  select *
                    from unnest(:runIds, :historyOffsets)
                      as t(run_id, history_offset)
                ),
                cte_history as (
                  select workflow_run_id
                       , event
                       , sequence_number
                    from dex_workflow_history as history
                   inner join cte_req
                      on history.workflow_run_id = cte_req.run_id
                     and history.sequence_number > cte_req.history_offset
                   order by workflow_run_id
                          , sequence_number
                ),
                cte_inbox as (
                  select id
                       , workflow_run_id
                       , event
                    from dex_workflow_inbox
                   where workflow_run_id in (select run_id from cte_req)
                     and visible_from <= now()
                   order by id
                )
                select 'HISTORY' as event_type
                     , workflow_run_id
                     , event
                     , sequence_number
                     , null as message_id
                  from cte_history
                 union all
                select 'INBOX' as event_type
                     , workflow_run_id
                     , event
                     , null as sequence_number
                     , id as message_id
                  from cte_inbox
                """);

        final var runIds = new UUID[requests.size()];
        final var historyOffsets = new int[requests.size()];

        int i = 0;
        for (final GetWorkflowRunHistoryRequest request : requests) {
            runIds[i] = request.runId();
            historyOffsets[i] = request.offset();
            i++;
        }

        final List<PolledWorkflowEvent> polledEvents = query
                .bind("runIds", runIds)
                .bind("historyOffsets", historyOffsets)
                .mapTo(PolledWorkflowEvent.class)
                .list();

        final var historyByRunId = new HashMap<UUID, List<WorkflowEvent>>(requests.size());
        final var inboxByRunId = new HashMap<UUID, List<WorkflowEvent>>(requests.size());
        final var maxHistorySequenceNumberByRunId = new HashMap<UUID, Integer>(requests.size());
        final var inboxMessageIdsByRunId = new HashMap<UUID, List<Long>>(requests.size());

        for (final PolledWorkflowEvent polledEvent : polledEvents) {
            switch (polledEvent.eventType()) {
                case HISTORY -> {
                    final List<WorkflowEvent> history = historyByRunId.computeIfAbsent(
                            polledEvent.workflowRunId(), _ -> new ArrayList<>());
                    history.add(polledEvent.event());

                    maxHistorySequenceNumberByRunId.compute(
                            polledEvent.workflowRunId(),
                            (_, previousMax) -> (previousMax == null || previousMax < polledEvent.historySequenceNumber())
                                    ? polledEvent.historySequenceNumber()
                                    : previousMax);
                }
                case INBOX -> {
                    final List<WorkflowEvent> inbox = inboxByRunId.computeIfAbsent(
                            polledEvent.workflowRunId(), _ -> new ArrayList<>());
                    inbox.add(polledEvent.event());

                    final List<Long> messageIds = inboxMessageIdsByRunId.computeIfAbsent(
                            polledEvent.workflowRunId(), _ -> new ArrayList<>());
                    messageIds.add(polledEvent.inboxMessageId());
                }
            }
        }

        final var polledEventsByRunId = new HashMap<UUID, PolledWorkflowEvents>(requests.size());
        for (final UUID runId : runIds) {
            polledEventsByRunId.put(runId, new PolledWorkflowEvents(
                    historyByRunId.getOrDefault(runId, Collections.emptyList()),
                    inboxByRunId.getOrDefault(runId, Collections.emptyList()),
                    maxHistorySequenceNumberByRunId.getOrDefault(runId, -1),
                    inboxMessageIdsByRunId.getOrDefault(runId, Collections.emptyList())));
        }

        return polledEventsByRunId;
    }

    public List<WorkflowEvent> getMessages(UUID runId) {
        final Query query = jdbiHandle.createQuery("""
                select event
                  from dex_workflow_inbox
                 where workflow_run_id = :runId
                 order by id
                """);

        return query
                .bind("runId", runId)
                .mapTo(WorkflowEvent.class)
                .list();
    }

    public int deleteMessages(Collection<DeleteWorkflowMessagesCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                with cte_cmd as (
                  select run_id
                       , cast(string_to_array(message_id_array, ',') as bigint[]) as message_ids
                    from unnest(:runIds, :messageIdArrays)
                      as t(run_id, message_id_array)
                )
                delete
                  from dex_workflow_inbox as inbox
                 using cte_cmd
                 where inbox.workflow_run_id = cte_cmd.run_id
                   and (cte_cmd.message_ids is null
                        or inbox.id = any(cte_cmd.message_ids))
                """);

        final var runIds = new UUID[commands.size()];
        final var messageIdArrays = new @Nullable String[commands.size()];

        int i = 0;
        for (final DeleteWorkflowMessagesCommand command : commands) {
            runIds[i] = command.workflowRunId();
            messageIdArrays[i] = command.messageIds() != null
                    ? command.messageIds().stream().map(String::valueOf).collect(Collectors.joining(","))
                    : null;
            i++;
        }

        return update
                .bind("runIds", runIds)
                .bind("messageIdArrays", messageIdArrays)
                .execute();
    }

    public int createRunHistoryEntries(Collection<CreateWorkflowRunHistoryEntryCommand> commands) {
        final Update update = jdbiHandle.createUpdate("""
                insert into dex_workflow_history (
                  workflow_run_id
                , sequence_number
                , event
                )
                select * from unnest(:runIds, :sequenceNumbers, :events)
                """);

        final var runIds = new UUID[commands.size()];
        final var sequenceNumbers = new int[commands.size()];
        final var events = new byte[commands.size()][];

        int i = 0;
        for (final CreateWorkflowRunHistoryEntryCommand command : commands) {
            runIds[i] = command.workflowRunId();
            sequenceNumbers[i] = command.sequenceNumber();
            events[i] = command.event().toByteArray();
            i++;
        }

        return update
                .bind("runIds", runIds)
                .bind("sequenceNumbers", sequenceNumbers)
                .bind("events", events)
                .execute();
    }

    public int truncateRunHistories(Collection<UUID> runIds) {
        final Update update = jdbiHandle.createUpdate("""
                delete
                  from dex_workflow_history
                 where workflow_run_id = any(:runIds)
                """);

        return update
                .bindArray("runIds", UUID.class, runIds)
                .execute();
    }

}
