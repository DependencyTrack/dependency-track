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
package org.dependencytrack.vulnanalysis;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.vulnanalysis.FindingDao.BATCH_SIZE;

class FindingDaoTest extends PersistenceCapableTest {

    @Test
    void createFindingsShouldCreateFindingsSpanningMultipleBatches() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        // Enough distinct (component, vulnerability) pairs to exceed one batch.
        final int count = (int) Math.ceil(Math.sqrt(BATCH_SIZE + 1));
        final var findingKeys = new ArrayList<FindingKey>(count * count);
        final List<Vulnerability> vulns = createVulns(count);
        for (int i = 0; i < count; i++) {
            final Component component = createComponent(project, "acme-lib-" + i);
            for (final Vulnerability vuln : vulns) {
                findingKeys.add(new FindingKey(component.getId(), vuln.getId()));
            }
        }

        useJdbiHandle(handle -> {
            final List<FindingKey> created = new FindingDao(handle).createFindings(findingKeys);

            assertThat(created).containsExactlyInAnyOrderElementsOf(findingKeys);
        });
    }

    @Test
    void createAttributionsShouldCreateAttributionsSpanningMultipleBatches() throws Exception {
        final List<FindingDao.CreateAttributionCommand> commands = createAttributionCommands(BATCH_SIZE + 1);

        useJdbiHandle(handle -> {
            final int created = new FindingDao(handle).createAttributions(commands);

            assertThat(created).isEqualTo(BATCH_SIZE + 1);
        });
    }

    @Test
    void deleteAttributionsShouldDeleteAttributionsSpanningMultipleBatches() throws Exception {
        final List<FindingDao.CreateAttributionCommand> commands = createAttributionCommands(BATCH_SIZE + 1);

        useJdbiHandle(
                handle -> {
                    final var dao = new FindingDao(handle);
                    dao.createAttributions(commands);
                    final List<Long> attributionIds =
                            dao.getExistingAttributions(commands.getFirst().projectId()).stream()
                                    .map(FindingDao.FindingAttribution::id)
                                    .toList();

                    final int deleted = dao.deleteAttributions(attributionIds);

                    assertThat(deleted).isEqualTo(BATCH_SIZE + 1);
                });
    }

    @Test
    void shouldThrowWhenInterruptedBeforeBatch() throws Exception {
        useJdbiHandle(handle -> {
            final var dao = new FindingDao(handle);

            Thread.currentThread().interrupt();
            assertThatExceptionOfType(InterruptedException.class)
                    .isThrownBy(() -> dao.createFindings(List.of(new FindingKey(1, 2))));

            Thread.currentThread().interrupt();
            assertThatExceptionOfType(InterruptedException.class)
                    .isThrownBy(() -> dao.createAttributions(
                            List.of(new FindingDao.CreateAttributionCommand(1, 2, 3, "foo", null))));

            Thread.currentThread().interrupt();
            assertThatExceptionOfType(InterruptedException.class).isThrownBy(() -> dao.deleteAttributions(List.of(1L)));
        });
    }

    private List<FindingDao.CreateAttributionCommand> createAttributionCommands(int count) {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Component component = createComponent(project, "acme-lib");
        final Vulnerability vuln = createVulns(1).getFirst();

        // Distinct analyzer names avoid having to create a component or vulnerability per attribution.
        final var commands = new ArrayList<FindingDao.CreateAttributionCommand>(count);
        for (int i = 0; i < count; i++) {
            commands.add(new FindingDao.CreateAttributionCommand(
                    vuln.getId(), component.getId(), project.getId(), "analyzer-" + i, null));
        }

        return commands;
    }

    private List<Vulnerability> createVulns(int count) {
        final var vulns = new ArrayList<Vulnerability>(count);
        for (int i = 0; i < count; i++) {
            final var vuln = new Vulnerability();
            vuln.setVulnId("INT-" + i);
            vuln.setSource(Vulnerability.Source.INTERNAL);
            vulns.add(qm.persist(vuln));
        }

        return vulns;
    }

    private Component createComponent(Project project, String name) {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        return qm.persist(component);
    }
}
