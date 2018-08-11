/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.event;

import org.dependencytrack.model.Component;
import java.util.List;

/**
 * Defines multiple event types to execute Dependency-Check in various ways.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class DependencyCheckEvent extends VulnerabilityAnalysisEvent {

    public enum Action {
        ANALYZE,
        UPDATE_ONLY
    }

    private Action action;

    public DependencyCheckEvent() {
        this.action = Action.ANALYZE;
    }

    public DependencyCheckEvent(Action action) {
        this.action = action;
    }

    public DependencyCheckEvent(Component component) {
        super(component);
        this.action = Action.ANALYZE;
    }

    public DependencyCheckEvent(List<Component> components) {
        super(components);
        this.action = Action.ANALYZE;
    }

    public Action getAction() {
        return action;
    }

}
