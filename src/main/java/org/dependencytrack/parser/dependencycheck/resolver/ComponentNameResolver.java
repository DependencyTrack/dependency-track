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
package org.dependencytrack.parser.dependencycheck.resolver;

import org.dependencytrack.parser.dependencycheck.model.Dependency;

import java.io.File;

/**
 * Attempts to resolve the name of the component from evidence
 * available in the specified dependency.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class ComponentNameResolver extends AbstractStringResolver implements IResolver {

    /**
     * {@inheritDoc}
     */
    public String resolve(Dependency dependency) {
        if (dependency.getEvidenceCollected() == null) {
            if (dependency.getFileName() != null) {
                return dependency.getFileName();
            } else if (dependency.getFilePath() != null) {
                File file = new File(dependency.getFilePath());
                return file.toPath().getFileName().toString();
            }
            return "unknown"; // a 'name' is required in order for a component to be persisted
        }
        /*
         * Attempts to use the product evidence first, if that is null, then
         * return the filename of the component (could be null).
         */
        String product = resolve(dependency, "product", 3);
        if (product != null) {
            return product;
        } else {
            return dependency.getFileName();
        }
    }

}
