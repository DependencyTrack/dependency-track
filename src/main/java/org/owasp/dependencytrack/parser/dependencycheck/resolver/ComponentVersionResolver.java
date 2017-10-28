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
import org.owasp.dependencytrack.parser.dependencycheck.model.Evidence;
import java.util.List;

/**
 * Attempts to resolve the version of the component from evidence
 * available in the specified dependency.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class ComponentVersionResolver implements IResolver {

    /**
     * {@inheritDoc}
     */
    public String resolve(Dependency dependency) {
        Evidence best = null;
        final List<Evidence> evidenceList = dependency.getEvidenceCollected();
        for (Evidence evidence: evidenceList) {
            // do not trust configure.in - all kinds of irrelevant stuff in there
            if ("version".equals(evidence.getType()) && !("configure.in".equals(evidence.getSource()))) {
                if ("file".equals(evidence.getSource()) && "HIGHEST".equals(evidence.getConfidence())) {
                    return evidence.getValue();
                }
                if (best == null || (evidence.getConfidenceScore() > best.getConfidenceScore())) {
                    if (evidence.getConfidenceScore() >= 2) { // We only want MEDIUM, HIGH or HIGHEST
                        best = evidence;
                    }
                }
            }
        }
        if (best != null) {
            return best.getValue();
        }
        return null;
    }
}
