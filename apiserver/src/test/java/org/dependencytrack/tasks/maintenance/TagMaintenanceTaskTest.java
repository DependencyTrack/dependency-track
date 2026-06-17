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
package org.dependencytrack.tasks.maintenance;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_TAGS_DELETE_UNUSED;

class TagMaintenanceTaskTest extends PersistenceCapableTest {

    @Test
    void test() {
        qm.createConfigProperty(
                MAINTENANCE_TAGS_DELETE_UNUSED.getGroupName(),
                MAINTENANCE_TAGS_DELETE_UNUSED.getPropertyName(),
                "true",
                MAINTENANCE_TAGS_DELETE_UNUSED.getPropertyType(),
                MAINTENANCE_TAGS_DELETE_UNUSED.getDescription());

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var policy = new Policy();
        policy.setName("foo-policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-123");
        vuln.setSource(Vulnerability.Source.NVD);
        qm.persist(vuln);

        qm.bind(project, List.of(qm.createTag("tag-project")));
        qm.bind(policy, List.of(qm.createTag("tag-policy")));
        qm.bind(vuln, List.of(qm.createTag("tag-vuln")));
        qm.createTag("tag-orphaned");

        final var task = new TagMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.run());

        assertThat(qm.getTags()).satisfiesExactlyInAnyOrder(
                tag -> assertThat(tag.name()).isEqualTo("tag-project"),
                tag -> assertThat(tag.name()).isEqualTo("tag-policy"),
                tag -> assertThat(tag.name()).isEqualTo("tag-vuln")
        );
    }

    @Test
    void testWithDeleteUnusedDisabled() {
        qm.createConfigProperty(
                MAINTENANCE_TAGS_DELETE_UNUSED.getGroupName(),
                MAINTENANCE_TAGS_DELETE_UNUSED.getPropertyName(),
                "false",
                MAINTENANCE_TAGS_DELETE_UNUSED.getPropertyType(),
                MAINTENANCE_TAGS_DELETE_UNUSED.getDescription());

        qm.createTag("tag-orphaned");

        final var task = new TagMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.run());

        assertThat(qm.getTags()).satisfiesExactly(
                tag -> assertThat(tag.name()).isEqualTo("tag-orphaned")
        );
    }

}