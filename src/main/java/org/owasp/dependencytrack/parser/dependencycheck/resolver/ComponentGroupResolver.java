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
package org.owasp.dependencytrack.parser.dependencycheck.resolver;

import org.owasp.dependencytrack.parser.dependencycheck.model.Dependency;

/**
 * Attempts to resolve the group of the component from evidence
 * available in the specified dependency.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class ComponentGroupResolver extends AbstractStringResolver implements IResolver {

    /**
     * {@inheritDoc}
     */
    public String resolve(Dependency dependency) {
        return resolve(dependency, "vendor", 3);
    }

}
