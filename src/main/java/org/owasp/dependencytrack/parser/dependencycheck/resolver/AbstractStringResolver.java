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
 * This class will resolve string-based evidence.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public abstract class AbstractStringResolver {

    /**
     * Attempts to resolve the most likely to be accurate evidence.
     * @param dependency the Dependency to extract evidence from
     * @param evidenceType the type of evidence to extract (typically: product, vendor, version)
     * @param minConfidenceScore the minimum confidence score
     * @return the highly confidence evidence, or null if not found or doesn't meet criteria
     */
    protected String resolve(Dependency dependency, String evidenceType, int minConfidenceScore) {
        Evidence best = null;
        final List<Evidence> evidenceList = dependency.getEvidenceCollected();
        for (Evidence evidence: evidenceList) {
            // do not trust configure.in - all kinds of irrelevant stuff in there
            if (evidenceType.equals(evidence.getType()) && !("configure.in".equals(evidence.getSource()))) {
                if (best == null || (evidence.getConfidenceScore() > best.getConfidenceScore())) {
                    if (evidence.getConfidenceScore() >= minConfidenceScore) {
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
