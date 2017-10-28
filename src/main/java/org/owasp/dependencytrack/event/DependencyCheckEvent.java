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
package org.owasp.dependencytrack.event;

import alpine.event.framework.Event;
import org.owasp.dependencytrack.model.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * Defines multiple event types to execute Dependency-Check in various ways.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class DependencyCheckEvent implements Event {

    public enum Action {
        ANALYZE,
        UPDATE_ONLY
    }

    private Action action;
    private List<Component> components = new ArrayList<>();

    public DependencyCheckEvent(Action action) {
        this.action = action;
    }

    public DependencyCheckEvent(Component component) {
        this.action = Action.ANALYZE;
        this.components.add(component);
    }

    public DependencyCheckEvent(List<Component> components) {
        this.action = Action.ANALYZE;
        this.components.addAll(components);
    }

    public Action getAction() {
        return action;
    }

    public List<Component> getComponents() {
        return this.components;
    }

    public boolean analyzePortfolio() {
        return components.size() == 0;
    }
}
