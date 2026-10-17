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
import org.dependencytrack.notification.proto.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class NotificationModelConverterTest {

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldIncludeProjectLatestStatus(boolean isLatest) throws Exception {
        final var project = new Project();
        project.setUuid(UUID.randomUUID());
        project.setName("projectName");
        project.setIsLatest(isLatest);

        final var converted = NotificationModelConverter.convert(project);
        assertThat(converted.hasIsLatest()).isTrue();
        assertThat(converted.getIsLatest()).isEqualTo(isLatest);

        final var expressionEnv = NotificationFilterExpressionEnv.getInstance();
        final var program = expressionEnv.compile("subject.project.is_latest == true");
        final var subject =
                BomConsumedOrProcessedSubject.newBuilder().setProject(converted).build();
        assertThat(expressionEnv.evaluate(program, Notification.getDefaultInstance(), subject))
                .isEqualTo(isLatest);
    }
}
