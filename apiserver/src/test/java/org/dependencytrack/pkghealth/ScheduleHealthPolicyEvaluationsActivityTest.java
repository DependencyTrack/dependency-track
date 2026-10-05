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
package org.dependencytrack.pkghealth;

import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.analysis.AnalyzeProjectWorkflow;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.pkgmetadata.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.PackageArtifactMetadataDao;
import org.dependencytrack.pkgmetadata.PackageMetadata;
import org.dependencytrack.pkgmetadata.PackageMetadataDao;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.dependencytrack.proto.internal.workflow.v1.ScheduleHealthPolicyEvaluationsArg;
import org.dependencytrack.util.PurlUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ScheduleHealthPolicyEvaluationsActivityTest extends PersistenceCapableTest {

    private DexEngine dexEngine;
    private ActivityContext context;
    private ScheduleHealthPolicyEvaluationsActivity activity;

    @BeforeEach
    void beforeEach() {
        dexEngine = mock(DexEngine.class);
        context = mock(ActivityContext.class);
        when(context.workflowRunId()).thenReturn(UUID.randomUUID());
        activity = new ScheduleHealthPolicyEvaluationsActivity(dexEngine);
    }

    @Test
    void shouldIgnoreNullArgument() {
        activity.execute(context, null);

        verifyNoInteractions(dexEngine);
    }

    @Test
    void shouldIgnoreEmptyPurlList() {
        activity.execute(context, ScheduleHealthPolicyEvaluationsArg.getDefaultInstance());

        verifyNoInteractions(dexEngine);
    }

    @Test
    void shouldSkipProjectsWhoseConditionsDoNotReadHealth() {
        final var policy = qm.createPolicy("name-policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(
                policy,
                PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES,
                "component.name == \"react\"",
                PolicyViolation.Type.OPERATIONAL);
        final var project = persistProjectWithComponent("acme-app", "pkg:npm/react@18.3.1");

        activity.execute(
                context,
                ScheduleHealthPolicyEvaluationsArg.newBuilder()
                        .addPurls("pkg:npm/react")
                        .build());

        verify(dexEngine, never()).createRuns(any());
        assertThat(project.getUuid()).isNotNull();
    }

    @Test
    void shouldScheduleEvaluationForProjectsThatUseThePackage() {
        final var policy = qm.createPolicy("health-policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(
                policy,
                PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES,
                "has(health.stars) && health.stars < 5",
                PolicyViolation.Type.OPERATIONAL);
        final var matchingProject = persistProjectWithComponent("acme-app", "pkg:npm/react@18.3.1");
        persistProjectWithComponent("other-app", "pkg:npm/left-pad@1.0.0");

        activity.execute(
                context,
                ScheduleHealthPolicyEvaluationsArg.newBuilder()
                        .addPurls("pkg:npm/react")
                        .build());

        @SuppressWarnings("unchecked")
        final ArgumentCaptor<Collection<CreateWorkflowRunRequest<?>>> captor =
                ArgumentCaptor.forClass(Collection.class);
        verify(dexEngine).createRuns(captor.capture());

        assertThat(captor.getValue()).singleElement().satisfies(request -> {
            assertThat(request.workflowName()).isEqualTo("eval-project-policies");
            assertThat(request.concurrencyKey())
                    .isEqualTo(AnalyzeProjectWorkflow.concurrencyKeyForProject(matchingProject.getUuid()));
            assertThat(request.argument())
                    .isEqualTo(EvalProjectPoliciesArg.newBuilder()
                            .setProjectUuid(matchingProject.getUuid().toString())
                            .build());
        });
    }

    private Project persistProjectWithComponent(final String projectName, final String purl) {
        final var project = new Project();
        project.setName(projectName);
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName(projectName + "-component");
        component.setPurl(purl);
        component.setPurlCoordinates(purl);
        qm.persist(component);
        persistArtifactMetadata(purl);
        return project;
    }

    /**
     * Package health is matched to components through their package artifact metadata.
     */
    private static void persistArtifactMetadata(final String purl) {
        final PackageURL artifactPurl = requireNonNull(PurlUtil.silentPurl(purl));
        final PackageURL packagePurl = requireNonNull(PurlUtil.silentPurlPackageOnly(artifactPurl));
        useJdbiHandle(handle -> {
            new PackageMetadataDao(handle)
                    .upsertAll(List.of(new PackageMetadata(packagePurl, null, null, Instant.now(), null, null)));
            new PackageArtifactMetadataDao(handle)
                    .upsertAll(List.of(new PackageArtifactMetadata(
                            artifactPurl, packagePurl, null, null, null, null, null, null, "test", Instant.now())));
        });
    }
}
