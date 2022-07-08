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
import org.dependencytrack.model.Project;

import java.util.Optional;
import java.util.UUID;

public class RepositoryMetaEvent implements Event {

    public enum Type {
        PORTFOLIO,
        PROJECT,
        COMPONENT
    }

    private final Type type;
    private final UUID target;

    public RepositoryMetaEvent() {
        this(Type.PORTFOLIO, null);
    }

    /**
     * @since 4.6.0
     */
    public RepositoryMetaEvent(final Project project) {
        this(Type.PROJECT, project.getUuid());
    }

    public RepositoryMetaEvent(final Component component) {
        this(Type.COMPONENT, component.getUuid());
    }

    private RepositoryMetaEvent(final Type type, final UUID target) {
        this.type = type;
        this.target = target;
    }

    /**
     * @return The {@link Type} of the target
     * @since 4.6.0
     */
    public Type getType() {
        return type;
    }

    /**
     * @return The {@link UUID} of the target
     * @since 4.6.0
     */
    public Optional<UUID> getTarget() {
        return Optional.ofNullable(target);
    }

}
