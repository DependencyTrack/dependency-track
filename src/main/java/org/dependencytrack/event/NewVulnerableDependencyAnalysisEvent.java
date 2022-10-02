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

import alpine.event.framework.Event;
import org.dependencytrack.model.Component;

import java.util.List;
import java.util.Objects;

/**
 * Defines an {@link Event} triggered when one or more new components have been added to a project.
 * <p>
 * The main purpose of this event is the delayed evaluation of notification criteria
 * for the {@link org.dependencytrack.notification.NotificationGroup#NEW_VULNERABLE_DEPENDENCY} group.@
 *
 * @since 4.6.0
 */
public record NewVulnerableDependencyAnalysisEvent(List<Component> components) implements Event {

    /**
     * @param components A {@link List} of {@link Component}s that are considered to be new
     */
    public NewVulnerableDependencyAnalysisEvent(final List<Component> components) {
        this.components = Objects.requireNonNull(components);
    }

}
