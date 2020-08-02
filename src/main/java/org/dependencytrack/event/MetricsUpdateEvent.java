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

import alpine.event.framework.SingletonCapableEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import java.util.UUID;

/**
 * Defines an Event to update metrics.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class MetricsUpdateEvent extends SingletonCapableEvent {

    public static final UUID PORTFOLIO_CHAIN_IDENTIFIER = UUID.fromString("1d652235-9480-4033-a24e-c748811e24d6");

    public enum Type {
        PORTFOLIO,
        PROJECT,
        COMPONENT,
        VULNERABILITY
    }

    private Type type = Type.PORTFOLIO;
    private Object target;

    // Call this to perform a metrics update on a specific project or component
    public MetricsUpdateEvent(final Object target) {
        if (target == null) {
            this.type = Type.PORTFOLIO;
            this.setChainIdentifier(PORTFOLIO_CHAIN_IDENTIFIER);
            this.setSingleton(true);
        } else if (target instanceof Project) {
            this.type = Type.PROJECT;
        } else if (target instanceof Component) {
            this.type = Type.COMPONENT;
        }
        this.target = target;
    }

    // Call this to perform metrics not related to the portfolio, projects, components, or dependencies.
    // For example, running metrics on vulnerabilities being tracked in the database.
    public MetricsUpdateEvent(final Type type) {
        this.type = type;
        if (Type.PORTFOLIO == type) {
            this.setChainIdentifier(PORTFOLIO_CHAIN_IDENTIFIER);
            this.setSingleton(true);
        }
    }

    public Type getType() {
        return type;
    }

    public Object getTarget() {
        return target;
    }

}
