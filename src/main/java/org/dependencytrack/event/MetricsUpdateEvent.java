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

import alpine.event.framework.Event;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Dependency;
import org.dependencytrack.model.Project;

/**
 * Defines an Event to update metrics.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class MetricsUpdateEvent implements Event {

    public enum Type {
        PORTFOLIO,
        PROJECT,
        COMPONENT,
        DEPENDENCY,
        VULNERABILITY
    }

    private Type type = Type.PORTFOLIO;
    private Object target = null;

    // Call this to perform a metrics update on a specific project or component
    public MetricsUpdateEvent(Object target) {
        if (target == null) {
            this.type = Type.PORTFOLIO;
        } else if (target instanceof Project) {
            this.type = Type.PROJECT;
        } else if (target instanceof Component) {
            this.type = Type.COMPONENT;
        } else if (target instanceof Dependency) {
            this.type = Type.DEPENDENCY;
        }
        this.target = target;
    }

    // Call this to perform metrics not related to the portfolio, projects, components, or dependencies.
    // For example, running metrics on vulnerabilities being tracked in the database.
    public MetricsUpdateEvent(Type type) {
        this.type = type;
    }

    public Type getType() {
        return type;
    }

    public Object getTarget() {
        return target;
    }

}
