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
package org.dependencytrack.analysis;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.response.CreateWorkflowRunResponse;
import org.dependencytrack.model.Project;
import org.dependencytrack.proto.internal.workflow.v1.AnalyzeProjectWorkflowArg;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.proto.internal.workflow.v1.AnalysisTrigger.ANALYSIS_TRIGGER_SCHEDULE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PortfolioAnalysisTaskTest extends PersistenceCapableTest {

    private static final Duration MAX_ANALYSIS_AGE = Duration.ofHours(24);
    private static final int MAX_IN_FLIGHT = 10;

    private final DexEngine dexEngineMock = mock(DexEngine.class);

    @Test
    void shouldCreateAnalysisRunsForDueProjects() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        when(dexEngineMock.countRuns(any())).thenReturn(0L);

        new PortfolioAnalysisTask(dexEngineMock, MAX_IN_FLIGHT, MAX_ANALYSIS_AGE).run();

        final ArgumentCaptor<Collection<? extends CreateWorkflowRunRequest<?>>> requestsCaptor =
                ArgumentCaptor.captor();
        verify(dexEngineMock).createRuns(requestsCaptor.capture());
        assertThat(requestsCaptor.getValue())
                .extracting(CreateWorkflowRunRequest::workflowInstanceId)
                .containsExactlyInAnyOrder(
                        "analyze-project-scheduled:" + projectA.getUuid(),
                        "analyze-project-scheduled:" + projectB.getUuid());
    }

    @Test
    void shouldCreateRunsWithConcurrencyKeyLabelsAndTrigger() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        when(dexEngineMock.countRuns(any())).thenReturn(0L);

        new PortfolioAnalysisTask(dexEngineMock, MAX_IN_FLIGHT, MAX_ANALYSIS_AGE).run();

        final ArgumentCaptor<Collection<? extends CreateWorkflowRunRequest<?>>> requestsCaptor =
                ArgumentCaptor.captor();
        verify(dexEngineMock).createRuns(requestsCaptor.capture());
        assertThat(requestsCaptor.getValue()).singleElement().satisfies(request -> {
            assertThat(request.workflowName()).isEqualTo("analyze-project");
            assertThat(request.concurrencyKey()).isEqualTo("analyze-project:" + project.getUuid());
            assertThat(request.priority()).isZero();
            assertThat(request.labels()).containsOnly(
                    Map.entry("project_uuid", project.getUuid().toString()),
                    Map.entry("analysis_trigger", "schedule"));
            assertThat(request.argument()).isInstanceOfSatisfying(
                    AnalyzeProjectWorkflowArg.class,
                    arg -> {
                        assertThat(arg.getProjectUuid()).isEqualTo(project.getUuid().toString());
                        assertThat(arg.getTrigger()).isEqualTo(ANALYSIS_TRIGGER_SCHEDULE);
                    });
        });
    }

    @Test
    void shouldNotCreateMoreRunsThanTheLimitAllows() {
        for (int i = 0; i < 5; i++) {
            final var project = new Project();
            project.setName("acme-app-" + i);
            qm.persist(project);
        }

        when(dexEngineMock.countRuns(any())).thenReturn(8L);

        new PortfolioAnalysisTask(dexEngineMock, MAX_IN_FLIGHT, MAX_ANALYSIS_AGE).run();

        final ArgumentCaptor<Collection<? extends CreateWorkflowRunRequest<?>>> requestsCaptor =
                ArgumentCaptor.captor();
        verify(dexEngineMock).createRuns(requestsCaptor.capture());
        assertThat(requestsCaptor.getValue()).hasSize(2);
    }

    @Test
    void shouldNotCreateRunsWhenLimitIsReached() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        when(dexEngineMock.countRuns(any())).thenReturn((long) MAX_IN_FLIGHT);

        new PortfolioAnalysisTask(dexEngineMock, MAX_IN_FLIGHT, MAX_ANALYSIS_AGE).run();

        verify(dexEngineMock, never()).createRuns(any());
    }

    @Test
    void shouldNotCreateRunsForInactiveProjects() {
        final var project = new Project();
        project.setName("acme-app-inactive");
        project.setInactiveSince(new Date());
        qm.persist(project);

        when(dexEngineMock.countRuns(any())).thenReturn(0L);

        new PortfolioAnalysisTask(dexEngineMock, MAX_IN_FLIGHT, MAX_ANALYSIS_AGE).run();

        verify(dexEngineMock, never()).createRuns(any());
    }

    @Test
    void shouldNotOfferTheSameProjectAgainWithinMaxAnalysisAge() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        when(dexEngineMock.countRuns(any())).thenReturn(0L);
        when(dexEngineMock.createRuns(any())).thenAnswer(invocation -> {
            final Collection<? extends CreateWorkflowRunRequest<?>> requests = invocation.getArgument(0);
            return requests.stream()
                    .map(request -> new CreateWorkflowRunResponse(request.requestId(), UUID.randomUUID()))
                    .toList();
        });

        final var task = new PortfolioAnalysisTask(dexEngineMock, MAX_IN_FLIGHT, MAX_ANALYSIS_AGE);
        task.run();
        task.run();

        verify(dexEngineMock, times(1)).createRuns(any());
    }

    @Test
    void shouldOfferProjectAgainWhenItsRunWasNotCreated() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        when(dexEngineMock.countRuns(any())).thenReturn(0L);
        when(dexEngineMock.createRuns(any())).thenReturn(List.of());

        final var task = new PortfolioAnalysisTask(dexEngineMock, MAX_IN_FLIGHT, MAX_ANALYSIS_AGE);
        task.run();
        task.run();

        verify(dexEngineMock, times(2)).createRuns(any());
    }

}
