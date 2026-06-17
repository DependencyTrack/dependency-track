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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class QueryManagerTest extends PersistenceCapableTest {

    @Test
    public void shouldRejectConvertingProjectWithComponentsToCollection() {
        var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, List.of(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.createComponent(component, false);

        var transientProject = new Project();
        transientProject.setUuid(project.getUuid());
        transientProject.setName(project.getName());
        transientProject.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);

        assertThatThrownBy(() -> qm.updateProject(transientProject, false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("A project with components or services cannot be converted to a collection project.");
    }

    @Test
    public void shouldRejectWithTagLogicWithoutTag() {
        var project = new Project();
        project.setName("acme-app");
        project.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG);

        assertThatThrownBy(() -> qm.createProject(project, List.of(), false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("A collection tag must be specified for AGGREGATE_DIRECT_CHILDREN_WITH_TAG logic.");
    }

    @Test
    public void shouldClearCollectionTagWhenLogicChanges() {
        final Tag prodTag = qm.createTag("prod");

        var project = new Project();
        project.setName("acme-app");
        project.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG);
        project.setCollectionTag(prodTag);
        qm.createProject(project, List.of(), false);

        var transientProject = new Project();
        transientProject.setUuid(project.getUuid());
        transientProject.setName(project.getName());
        transientProject.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        final Project updated = qm.updateProject(transientProject, false);

        assertThat(updated.getCollectionTag()).isNull();
    }

}
