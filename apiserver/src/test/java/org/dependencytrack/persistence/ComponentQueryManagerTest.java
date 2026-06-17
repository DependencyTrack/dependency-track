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
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class ComponentQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testGetComponentsByPurl() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component1 = new Component();
        component1.setProject(project);
        component1.setName("acme-lib-a");
        component1.setVersion("1.0.1");
        component1.setPurl("pkg:maven/foo/bar@1.2.3");
        component1.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        component1.setMd5("098f6bcd4621d373cade4e832627b4f6");
        component1.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        qm.persist(component1);

        final var component2 = new Component();
        component2.setProject(project);
        component2.setProject(project);
        component2.setName("acme-lib");
        component2.setVersion("1.0.1");
        component2.setPurl("pkg:maven/foo/bar@1.2.3");
        component2.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        component2.setMd5("098f6bcd4621d373cade4e832627b4f6");
        component2.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        qm.persist(component2);

        List<Component> components = qm.getComponentsByPurl("pkg:maven/foo/bar@1.2.3");
        assertThat(components).isNotNull();
        assertThat(components).hasSize(2);
        assertThat(components).satisfiesExactlyInAnyOrder(component -> {
                    assertThat(component.getMd5()).isEqualTo("098f6bcd4621d373cade4e832627b4f6");
                    assertThat(component.getSha1()).isEqualTo("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
                },
                component -> {
                    assertThat(component.getMd5()).isEqualTo("098f6bcd4621d373cade4e832627b4f6");
                    assertThat(component.getSha1()).isEqualTo("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
                });
    }
}