/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.event;

import alpine.event.framework.Event;
import org.owasp.dependencytrack.model.Component;
import java.util.ArrayList;
import java.util.List;

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

