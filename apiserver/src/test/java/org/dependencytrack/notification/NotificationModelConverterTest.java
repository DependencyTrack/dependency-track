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
package org.dependencytrack.notification;

import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class NotificationModelConverterTest {

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldConvertProject(boolean isLatest) {
        final var tag = new Tag();
        tag.setName("projectTag");

        final var project = new Project();
        project.setUuid(UUID.randomUUID());
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setDescription("projectDescription");
        project.setPurl("pkg:generic/project@1.0");
        project.setTags(Set.of(tag));
        project.setActive(false);
        project.setIsLatest(isLatest);

        assertThat(NotificationModelConverter.convert(project))
                .isEqualTo(org.dependencytrack.notification.proto.v1.Project.newBuilder()
                        .setUuid(project.getUuid().toString())
                        .setName("projectName")
                        .setVersion("projectVersion")
                        .setDescription("projectDescription")
                        .setPurl("pkg:generic/project@1.0")
                        .addTags("projectTag")
                        .setIsActive(false)
                        .setIsLatest(isLatest)
                        .build());
    }
}
