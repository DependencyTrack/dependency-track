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
package org.dependencytrack.persistence.jdbi;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ProjectDaoDeletionTest {

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldOnlyReturnOriginalBomFilesForDeletedProjects(boolean deleteParent) {
        final var parentUuid = UUID.randomUUID();
        final var childUuid = UUID.randomUUID();
        final var survivingUuid = UUID.randomUUID();
        final var projectUuids = List.of(parentUuid, survivingUuid);
        final var parentFile = new ProjectDao.OriginalBomFileMetadataRow(parentUuid, new byte[] {1});
        final var childFile = new ProjectDao.OriginalBomFileMetadataRow(childUuid, new byte[] {2});
        final var survivingFile = new ProjectDao.OriginalBomFileMetadataRow(survivingUuid, new byte[] {3});
        final List<ProjectDao.DeletedProjectRow> deletedProjects = deleteParent
                ? List.of(
                        new ProjectDao.DeletedProjectRow(parentUuid, "parent", null, null),
                        new ProjectDao.DeletedProjectRow(childUuid, "child", null, parentUuid))
                : List.of();

        final var dao = mock(ProjectDao.class);
        when(dao.deleteProjectsWithOriginalBomFiles(projectUuids)).thenCallRealMethod();
        when(dao.getOriginalBomFileMetadataForProjects(projectUuids))
                .thenReturn(List.of(parentFile, childFile, survivingFile));
        // Simulate access being revoked after metadata was collected.
        when(dao.deleteProjects(projectUuids)).thenReturn(deletedProjects);

        final var result = dao.deleteProjectsWithOriginalBomFiles(projectUuids);

        assertThat(result.deletedProjects()).containsExactlyElementsOf(deletedProjects);
        assertThat(result.originalBomFiles())
                .containsExactlyElementsOf(deleteParent ? List.of(parentFile, childFile) : List.of());
    }
}
