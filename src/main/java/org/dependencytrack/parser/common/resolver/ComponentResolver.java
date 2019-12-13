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
package org.dependencytrack.parser.common.resolver;

import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.QueryManager;

/**
 * Attempts to resolve an existing Dependency-Track Component.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class ComponentResolver {

    private final QueryManager qm;

    public ComponentResolver(final QueryManager qm) {
        this.qm = qm;
    }

    public Component resolve(final Component component) {
        Component resolvedComponent = qm.getComponentByHash(component.getMd5());
        if (resolvedComponent != null) {
            return resolvedComponent;
        }
        resolvedComponent = qm.getComponentByHash(component.getSha1());
        if (resolvedComponent != null) {
            return resolvedComponent;
        }
        resolvedComponent = qm.getComponentByHash(component.getSha256());
        if (resolvedComponent != null) {
            return resolvedComponent;
        }
        resolvedComponent = qm.getComponentByHash(component.getSha512());
        if (resolvedComponent != null) {
            return resolvedComponent;
        }
        resolvedComponent = qm.getComponentByHash(component.getSha3_256());
        if (resolvedComponent != null) {
            return resolvedComponent;
        }
        resolvedComponent = qm.getComponentByHash(component.getSha3_512());
        if (resolvedComponent != null) {
            return resolvedComponent;
        }
        resolvedComponent = qm.getComponentByAttributes(component.getGroup(), component.getName(), component.getVersion());
        if (resolvedComponent != null) {
            return resolvedComponent;
        }
        return null;
    }

}
