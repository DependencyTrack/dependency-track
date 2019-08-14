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
package org.dependencytrack.parser.dependencycheck.model;

import org.apache.commons.lang3.StringUtils;

/**
 * Defines a base object that provides helper methods used to
 * determine confidence of evidence used in identifying components.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public abstract class BaseObject {

    protected String normalize(final String string) {
        return StringUtils.normalizeSpace(StringUtils.trimToNull(string));
    }

    public int getConfidenceScore(final String confidence) {
        switch (confidence) {
            case "HIGHEST":
                return 4;
            case "HIGH":
                return 3;
            case "MEDIUM":
                return 2;
            case "LOW":
                return 1;
            default:
                return 1;
        }
    }
}

