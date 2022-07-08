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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.event;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.junit.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class RepositoryMetaEventTest {

    @Test
    public void testDefaultConstructor() {
        final var event = new RepositoryMetaEvent();
        assertThat(event.getType()).isEqualTo(RepositoryMetaEvent.Type.PORTFOLIO);
        assertThat(event.getTarget()).isNotPresent();
    }

    @Test
    public void testProjectConstructor() {
        final var project = new Project();
        var event = new RepositoryMetaEvent(project);
        assertThat(event.getType()).isEqualTo(RepositoryMetaEvent.Type.PROJECT);
        assertThat(event.getTarget()).isNotPresent();

        final var uuid = UUID.randomUUID();
        project.setUuid(uuid);
        event = new RepositoryMetaEvent(project);
        assertThat(event.getType()).isEqualTo(RepositoryMetaEvent.Type.PROJECT);
        assertThat(event.getTarget()).contains(uuid);
    }

    @Test
    public void testComponentConstructor() {
        final var component = new Component();
        var event = new RepositoryMetaEvent(component);
        assertThat(event.getType()).isEqualTo(RepositoryMetaEvent.Type.COMPONENT);
        assertThat(event.getTarget()).isNotPresent();

        final var uuid = UUID.randomUUID();
        component.setUuid(uuid);
        event = new RepositoryMetaEvent(component);
        assertThat(event.getType()).isEqualTo(RepositoryMetaEvent.Type.COMPONENT);
        assertThat(event.getTarget()).contains(uuid);
    }
}
