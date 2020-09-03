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

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Component;

public interface CacheableScanTask extends ScanTask {

    /**
     * Determines if the analyzer should be executed
     * against a component with the specified PackageURL
     * @param packageUrl a PackageURL
     * @return true if the analyzer should be executed, false if not
     * @since 4.0.0
     */
    boolean shouldAnalyze(PackageURL packageUrl);

    /**
     * Analyzes the specified component from local {@link org.dependencytrack.model.ComponentAnalysisCache}.
     * @param component component the Component to analyze from cache
     * @since 4.0.0
     */
    void applyAnalysisFromCache(final Component component);

}
