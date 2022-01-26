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
package org.dependencytrack.tasks.scanners;

import org.dependencytrack.model.Component;
import java.util.List;

/**
 * An interface that defines vulnerability scanners that are implemented as Subscribers.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public interface ScanTask {

    /**
     * Returns the name of the analyzer.
     * @since 4.0.0
     */
    AnalyzerIdentity getAnalyzerIdentity();

    /**
     * Analyzes only the specified components.
     * @param components the components to analyze
     * @since 3.0.0
     */
    void analyze(List<Component> components);

    /**
     * Determines if the analyzer is capable of analyzing a component.
     * @param component a Component
     * @return true if the analyzer is capable of analyzing this type, false if not
     * @since 4.0.0
     */
    boolean isCapable(Component component);

}
