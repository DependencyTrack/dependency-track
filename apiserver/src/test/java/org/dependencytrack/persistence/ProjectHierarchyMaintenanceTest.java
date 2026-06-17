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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.jdo.Query;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class ProjectHierarchyMaintenanceTest extends PersistenceCapableTest {

    private Project parentProject;
    private Project childProject;
    private Project grandChildProjectA;
    private Project grandChildProjectB;

    @BeforeEach
    @Override
    public void before() throws Exception {
        super.before();

        parentProject = new Project();
        parentProject.setName("acme-app-parent");
        qm.persist(parentProject);

        childProject = new Project();
        childProject.setParent(parentProject);
        childProject.setName("acme-app-child");
        qm.persist(childProject);

        grandChildProjectA = new Project();
        grandChildProjectA.setParent(childProject);
        grandChildProjectA.setName("acme-app-grandchild-a");
        qm.persist(grandChildProjectA);

        grandChildProjectB = new Project();
        grandChildProjectB.setParent(childProject);
        grandChildProjectB.setName("acme-app-grandchild-b");
        qm.persist(grandChildProjectB);
    }

    @Test
    public void shouldMaintainHierarchyOnProjectCreation() {
        // + acme-app-parent
        // \-+ acme-app-child
        //   |-+ acme-app-grandchild-a
        //   \-+ acme-app-grandchild-b
        assertThat(getAllProjectHierarchies()).satisfiesExactlyInAnyOrder(
                // Self-referential records.
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.depth()).isEqualTo(0);
                },
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(childProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(childProject.getId());
                    assertThat(record.depth()).isEqualTo(0);
                },
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(grandChildProjectA.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectA.getId());
                    assertThat(record.depth()).isEqualTo(0);
                },
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(grandChildProjectB.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectB.getId());
                    assertThat(record.depth()).isEqualTo(0);
                },
                // acme-app-parent -> acme-app-child
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(childProject.getId());
                    assertThat(record.depth()).isEqualTo(1);
                },
                // acme-app-child -> acme-app-grandchild-a
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(childProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectA.getId());
                    assertThat(record.depth()).isEqualTo(1);
                },
                // acme-app-child -> acme-app-grandchild-b
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(childProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectB.getId());
                    assertThat(record.depth()).isEqualTo(1);
                },
                // acme-app-parent -> acme-app-grandchild-a
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectA.getId());
                    assertThat(record.depth()).isEqualTo(2);
                },
                // acme-app-parent -> acme-app-grandchild-b
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectB.getId());
                    assertThat(record.depth()).isEqualTo(2);
                });
    }

    @Test
    public void shouldMaintainHierarchyOnProjectUpdate() {
        final Project newChildProject = qm.callInTransaction(() -> {
            final var project = new Project();
            project.setParent(parentProject);
            project.setName("acme-app-child-new");
            qm.persist(project);

            grandChildProjectA.setParent(project);
            grandChildProjectB.setParent(project);

            return project;
        });

        // + acme-app-parent
        // |-+ acme-app-child
        // \-+ acme-app-child-new
        //   |-+ acme-app-grandchild-a
        //   \-+ acme-app-grandchild-b
        assertThat(getAllProjectHierarchies()).satisfiesExactlyInAnyOrder(
                // Self-referential records.
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.depth()).isEqualTo(0);
                },
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(childProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(childProject.getId());
                    assertThat(record.depth()).isEqualTo(0);
                },
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(newChildProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(newChildProject.getId());
                    assertThat(record.depth()).isEqualTo(0);
                },
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(grandChildProjectA.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectA.getId());
                    assertThat(record.depth()).isEqualTo(0);
                },
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(grandChildProjectB.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectB.getId());
                    assertThat(record.depth()).isEqualTo(0);
                },
                // acme-app-parent -> acme-app-child
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(childProject.getId());
                    assertThat(record.depth()).isEqualTo(1);
                },
                // acme-app-parent -> acme-app-child-new
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(newChildProject.getId());
                    assertThat(record.depth()).isEqualTo(1);
                },
                // acme-app-child-new -> acme-app-grandchild-a
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(newChildProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectA.getId());
                    assertThat(record.depth()).isEqualTo(1);
                },
                // acme-app-child-new -> acme-app-grandchild-b
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(newChildProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectB.getId());
                    assertThat(record.depth()).isEqualTo(1);
                },
                // acme-app-parent -> acme-app-grandchild-a
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectA.getId());
                    assertThat(record.depth()).isEqualTo(2);
                },
                // acme-app-parent -> acme-app-grandchild-b
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectB.getId());
                    assertThat(record.depth()).isEqualTo(2);
                });
    }

    @Test
    public void shouldMaintainHierarchyOnParentProjectDeletion() {
        withJdbiHandle(handle -> handle.attach(ProjectDao.class).deleteProject(parentProject.getUuid()));

        assertThat(getAllProjectHierarchies()).isEmpty();
    }

    @Test
    public void shouldMaintainHierarchyOnChildProjectDeletion() {
        withJdbiHandle(handle -> handle.attach(ProjectDao.class).deleteProject(childProject.getUuid()));

        // + acme-app-parent
        assertThat(getAllProjectHierarchies()).satisfiesExactlyInAnyOrder(
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.depth()).isEqualTo(0);
                });
    }

    @Test
    public void shouldMaintainHierarchyOnGrandChildProjectDeletion() {
        withJdbiHandle(handle -> handle.attach(ProjectDao.class).deleteProject(grandChildProjectA.getUuid()));

        // + acme-app-parent
        // \-+ acme-app-child
        //   \-+ acme-app-grandchild-b
        assertThat(getAllProjectHierarchies()).satisfiesExactlyInAnyOrder(
                // Self-referential records.
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.depth()).isEqualTo(0);
                },
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(childProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(childProject.getId());
                    assertThat(record.depth()).isEqualTo(0);
                },
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(grandChildProjectB.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectB.getId());
                    assertThat(record.depth()).isEqualTo(0);
                },
                // acme-app-parent -> acme-app-child
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(childProject.getId());
                    assertThat(record.depth()).isEqualTo(1);
                },
                // acme-app-child -> acme-app-grandchild-b
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(childProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectB.getId());
                    assertThat(record.depth()).isEqualTo(1);
                },
                // acme-app-parent -> acme-app-grandchild-b
                record -> {
                    assertThat(record.parentProjectId()).isEqualTo(parentProject.getId());
                    assertThat(record.childProjectId()).isEqualTo(grandChildProjectB.getId());
                    assertThat(record.depth()).isEqualTo(2);
                });
    }

    public record ProjectHierarchyRecord(long parentProjectId, long childProjectId, int depth) {
    }

    private List<ProjectHierarchyRecord> getAllProjectHierarchies() {
        final Query<?> query = qm.getPersistenceManager().newQuery(Query.SQL, /* language=SQL */ """
                SELECT * FROM "PROJECT_HIERARCHY"
                """);
        try {
            return List.copyOf(query.executeResultList(ProjectHierarchyRecord.class));
        } finally {
            query.closeAll();
        }
    }

}
