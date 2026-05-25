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
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.SortDirection;
import org.dependencytrack.dex.engine.api.WorkflowRunHistoryEntry;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.ExistsWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunHistoryRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.generic.GenericType;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public final class WorkflowRunDao extends AbstractDao {

    public WorkflowRunDao(final Handle jdbiHandle) {
        super(jdbiHandle);
    }

    record ListRunsPageToken(
            UUID lastId,
            long lastCreatedAt,
            @Nullable Long lastCompletedAt,
            ListWorkflowRunsRequest.SortBy sortBy,
            SortDirection sortDirection,
            TotalCount totalCount) implements PageToken {
    }

    public boolean existsRun(ExistsWorkflowRunRequest request) {
        requireNonNull(request, "request must not be null");

        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="statuses" type="boolean" -->
                <#-- @ftlvariable name="labels" type="boolean" -->
                select exists(
                  select 1
                    from dex_workflow_run
                   where true
                  <#if statuses!false>
                     and status = ANY(:statuses)
                  </#if>
                  <#if labels!false>
                     and labels @> cast(:labels as jsonb)
                  </#if>
                )
                """);

        if (request.statuses() != null && !request.statuses().isEmpty()) {
            query.bind(
                    "statuses",
                    request.statuses().stream()
                            .map(WorkflowRunStatus::name)
                            .toArray(String[]::new));
        }
        if (request.labels() != null && !request.labels().isEmpty()) {
            final JsonMapper.TypedJsonMapper jsonMapper = jdbiHandle
                    .getConfig(JsonConfig.class).getJsonMapper()
                    .forType(new GenericType<Map<String, String>>() {
                    }.getType(), jdbiHandle.getConfig());
            query.bind("labels", jsonMapper.toJson(
                    request.labels(), jdbiHandle.getConfig()));
        }

        return query
                .defineNamedBindings()
                .mapTo(boolean.class)
                .one();
    }

    public Page<WorkflowRunMetadata> listRuns(final ListWorkflowRunsRequest request) {
        requireNonNull(request, "request must not be null");

        final var whereConditions = new ArrayList<String>();
        whereConditions.add("true");

        final var queryParams = new HashMap<String, Object>();

        if (request.workflowName() != null) {
            whereConditions.add("workflow_name = :workflowName");
            queryParams.put("workflowName", request.workflowName());
        }
        if (request.workflowVersion() != null) {
            whereConditions.add("workflow_version = :workflowVersion");
            queryParams.put("workflowVersion", request.workflowVersion());
        }
        if (request.workflowInstanceId() != null) {
            whereConditions.add("workflow_instance_id = :workflowInstanceId");
            queryParams.put("workflowInstanceId", request.workflowInstanceId());
        }
        if (request.statuses() != null && !request.statuses().isEmpty()) {
            whereConditions.add("status = ANY(:statuses)");
            queryParams.put(
                    "statuses",
                    request.statuses().stream()
                            .map(WorkflowRunStatus::name)
                            .toArray(String[]::new));
        }
        if (request.labels() != null && !request.labels().isEmpty()) {
            final JsonMapper.TypedJsonMapper jsonMapper = jdbiHandle
                    .getConfig(JsonConfig.class).getJsonMapper()
                    .forType(new GenericType<Map<String, String>>() {
                    }.getType(), jdbiHandle.getConfig());
            final String labelsJson = jsonMapper.toJson(
                    request.labels(), jdbiHandle.getConfig());

            whereConditions.add("labels @> cast(:labels as jsonb)");
            queryParams.put("labels", labelsJson);
        }
        if (request.createdSince() != null) {
            whereConditions.add("created_at >= :createdSince");
            queryParams.put("createdSince", request.createdSince());
        }
        if (request.createdBefore() != null) {
            whereConditions.add("created_at < :createdBefore");
            queryParams.put("createdBefore", request.createdBefore());
        }
        if (request.completedSince() != null) {
            whereConditions.add("completed_at >= :completedSince");
            queryParams.put("completedSince", request.completedSince());
        }
        if (request.completedBefore() != null) {
            whereConditions.add("completed_at < :completedBefore");
            queryParams.put("completedBefore", request.completedBefore());
        }

        final var decodedPageToken = decodePageToken(request.pageToken(), ListRunsPageToken.class);

        TotalCount totalCount;
        UUID lastId = null;
        Instant lastCreatedAt = null;
        Instant lastCompletedAt = null;
        ListWorkflowRunsRequest.SortBy sortBy;
        SortDirection sortDirection;

        if (decodedPageToken != null) {
            totalCount = decodedPageToken.totalCount();
            lastId = decodedPageToken.lastId();
            lastCreatedAt = Instant.ofEpochMilli(decodedPageToken.lastCreatedAt());
            lastCompletedAt = decodedPageToken.lastCompletedAt() != null
                    ? Instant.ofEpochMilli(decodedPageToken.lastCompletedAt())
                    : null;
            sortBy = decodedPageToken.sortBy();
            sortDirection = decodedPageToken.sortDirection();
        } else {
            // When no page token was provided (i.e., first page was requested),
            // determine the total number of records across all pages.
            // Since count queries are expensive, and the table is expected to
            // hold a lot of records, only count up to 5001 records.
            //
            // Note that this query must not contain the keyset pagination conditions
            // since that would cause it to report inaccurate results.
            final Query totalCountQuery = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                    <#-- @ftlvariable name="whereConditions" type="java.util.Collection<String>" -->
                    select count(*)
                      from (
                        select 1
                          from dex_workflow_run
                         where ${whereConditions?join(" and ")}
                         limit 5001
                      ) as t
                    """);
            final long totalCountValue = totalCountQuery
                    .define("whereConditions", whereConditions)
                    .bindMap(queryParams)
                    .mapTo(long.class)
                    .one();
            totalCount = new TotalCount(
                    Math.min(totalCountValue, 5000),
                    totalCountValue > 5000
                            ? TotalCount.Type.AT_LEAST
                            : TotalCount.Type.EXACT);
            sortBy = request.sortBy() == null
                    ? ListWorkflowRunsRequest.SortBy.ID
                    : request.sortBy();
            sortDirection = request.sortDirection() == null
                    ? SortDirection.DESC
                    : request.sortDirection();
        }

        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="lastCompletedAt" type="boolean" -->
                <#-- @ftlvariable name="lastCreatedAt" type="boolean" -->
                <#-- @ftlvariable name="lastId" type="boolean" -->
                <#-- @ftlvariable name="sortBy" type="org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest.SortBy" -->
                <#-- @ftlvariable name="sortDirection" type="org.dependencytrack.common.pagination.SortDirection" -->
                <#-- @ftlvariable name="whereConditions" type="java.util.Collection<String>" -->
                select *
                  from dex_workflow_run
                 where ${whereConditions?join(" and ")}
                <#if sortBy == 'CREATED_AT'>
                  <#if sortDirection == 'ASC'>
                    <#if lastCreatedAt && lastId>
                      and (created_at > :lastCreatedAt or (created_at = :lastCreatedAt and id > :lastId))
                    </#if>
                    order by created_at asc, id asc
                  <#else>
                    <#if lastCreatedAt && lastId>
                      and (created_at < :lastCreatedAt or (created_at = :lastCreatedAt and id < :lastId))
                    </#if>
                    order by created_at desc, id desc
                  </#if>
                <#elseif sortBy == 'COMPLETED_AT'>
                  <#if sortDirection == 'ASC'>
                    <#if lastCompletedAt && lastId>
                      and (completed_at > :lastCompletedAt or (completed_at = :lastCompletedAt and id > :lastId))
                    </#if>
                    order by completed_at asc nulls last, id asc nulls first
                  <#else>
                    <#if lastCompletedAt && lastId>
                      and (completed_at < :lastCompletedAt or (completed_at = :lastCompletedAt and id < :lastId))
                    </#if>
                    order by completed_at desc nulls first, id desc
                  </#if>
                <#else>
                  <#if sortDirection == 'ASC'>
                    <#if lastId>
                      and id > :lastId
                    </#if>
                    order by id
                  <#else>
                    <#if lastId>
                      and id < :lastId
                    </#if>
                    order by id desc
                  </#if>
                </#if>
                 limit (:limit + 1)
                """);

        final List<WorkflowRunMetadata> rows = query
                .bindMap(queryParams)
                .bind("lastId", lastId)
                .bind("lastCreatedAt", lastCreatedAt)
                .bind("lastCompletedAt", lastCompletedAt)
                .bind("limit", request.limit())
                .define("whereConditions", whereConditions)
                .define("sortBy", sortBy)
                .define("sortDirection", sortDirection)
                .defineNamedBindings()
                .mapTo(WorkflowRunMetadata.class)
                .list();

        final List<WorkflowRunMetadata> resultItems = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), request.limit()))
                : rows;

        final ListRunsPageToken nextPageToken = rows.size() == (request.limit() + 1)
                ? new ListRunsPageToken(
                resultItems.getLast().id(),
                resultItems.getLast().createdAt().toEpochMilli(),
                resultItems.getLast().completedAt() != null
                        ? resultItems.getLast().completedAt().toEpochMilli()
                        : null,
                sortBy,
                sortDirection,
                totalCount)
                : null;

        return new Page<>(resultItems, encodePageToken(nextPageToken), totalCount);
    }

    record ListRunHistoryPageToken(
            @Nullable Integer fromSequenceNumber,
            int lastSequenceNumber,
            SortDirection sortDirection) implements PageToken {
    }

    public Page<WorkflowRunHistoryEntry> listRunHistory(ListWorkflowRunHistoryRequest request) {
        requireNonNull(request, "request must not be null");

        final var decodedPageToken = decodePageToken(request.pageToken(), ListRunHistoryPageToken.class);

        final Integer fromSequenceNumber;
        final SortDirection sortDirection;
        final int lastSequenceNumber;

        if (decodedPageToken != null) {
            fromSequenceNumber = decodedPageToken.fromSequenceNumber();
            sortDirection = decodedPageToken.sortDirection();
            lastSequenceNumber = decodedPageToken.lastSequenceNumber();
        } else {
            fromSequenceNumber = request.fromSequenceNumber();
            sortDirection = request.sortDirection() == null ? SortDirection.ASC : request.sortDirection();
            if (sortDirection == SortDirection.DESC) {
                lastSequenceNumber = Integer.MAX_VALUE;
            } else if (fromSequenceNumber != null) {
                lastSequenceNumber = fromSequenceNumber;
            } else {
                lastSequenceNumber = -1;
            }
        }

        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="sortDirection" type="org.dependencytrack.common.pagination.SortDirection" -->
                <#-- @ftlvariable name="fromSequenceNumber" type="boolean" -->
                select *
                  from dex_workflow_history
                 where workflow_run_id = :runId
                <#if sortDirection == 'ASC'>
                   and sequence_number > :lastSequenceNumber
                 order by sequence_number
                <#else>
                  <#if fromSequenceNumber>
                   and sequence_number > :fromSequenceNumber
                  </#if>
                   and sequence_number < :lastSequenceNumber
                 order by sequence_number desc
                </#if>
                 limit :limit
                """);

        final List<WorkflowRunHistoryEntry> rows = query
                .bind("runId", request.runId())
                .bind("fromSequenceNumber", fromSequenceNumber)
                .bind("lastSequenceNumber", lastSequenceNumber)
                .bind("limit", request.limit() + 1)
                .define("sortDirection", sortDirection)
                .defineNamedBindings()
                .mapTo(WorkflowRunHistoryEntry.class)
                .list();

        final List<WorkflowRunHistoryEntry> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), request.limit()))
                : rows;

        final ListRunHistoryPageToken nextPageToken = rows.size() == (request.limit() + 1)
                ? new ListRunHistoryPageToken(
                fromSequenceNumber,
                resultRows.getLast().sequenceNumber(),
                sortDirection)
                : null;

        return new Page<>(resultRows, encodePageToken(nextPageToken));
    }

}
