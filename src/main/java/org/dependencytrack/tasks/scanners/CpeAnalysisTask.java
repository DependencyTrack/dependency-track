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

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import com.github.packageurl.PackageURL;
import org.dependencytrack.event.CpeAnalysisEvent;
import org.dependencytrack.model.Component;
import java.util.List;

/**
 * Subscriber task that performs an analysis of component using internal CPE data.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public class CpeAnalysisTask extends BaseComponentAnalyzerTask implements Subscriber {

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof CpeAnalysisEvent) {

        }
    }

    /**
     * Determines if the {@link CpeAnalysisTask} is suitable for analysis based on the PackageURL.
     *
     * @param purl the PackageURL to analyze
     * @return true if CpeAnalysisTask should analyze, false if not
     */
    public boolean shouldAnalyze(final PackageURL purl) {
        return purl != null;
    }

    /**
     * Analyzes a list of Components.
     * @param components a list of Components
     */
    public void analyze(final List<Component> components) {

    }
}
