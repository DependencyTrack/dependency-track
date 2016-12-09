/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.parser.dependencycheck.model;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.dependency.Confidence;

public abstract class BaseObject {

    String cleanAndTrim(String string) {
        return StringUtils.normalizeSpace(StringUtils.trimToNull(string));
    }

    String trim(String string) {
        return StringUtils.trimToNull(string);
    }

    Confidence getConfidenceFromString(String confidence) {
        switch (cleanAndTrim(confidence)) {
            case "HIGHEST":
                return Confidence.HIGHEST;
            case "HIGH":
                return Confidence.HIGH;
            case "MEDIUM":
                return Confidence.MEDIUM;
            case "LOW":
                return Confidence.LOW;
            default:
                return Confidence.LOW;
        }
    }

    public int getConfidenceScore(Confidence confidence) {
        switch (confidence.name()) {
            case "HIGHEST":
                return 1;
            case "HIGH":
                return 2;
            case "MEDIUM":
                return 3;
            case "LOW":
                return 4;
            default:
                return 4;
        }
    }

}

