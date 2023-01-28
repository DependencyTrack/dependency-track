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
package org.dependencytrack.policy;

/**
 * Reusable methods that PolicyEvaluator implementations can extend.
 *
 * @author Roland Asmann
 * @since 4.8.0
 */
public final class Matcher {

    private Matcher() {
      // Utility-class should not be instantiated
    }

    /**
     * Check if the given value matches with the conditionString. If the
     * conditionString is not a regular expression, turn it into one.
     * 
     * @param value           The value to match against
     * @param conditionString The condition that should match -- may or may not be a
     *                        regular expression
     * @return <code>true</code> if the value matches the conditionString
     */
    static boolean matches(String value, String conditionString) {
        if (value == null && conditionString == null) {
            return true;
        }
        if (value == null ^ conditionString == null) {
            return false;
        }
        conditionString = conditionString.replace("*", ".*").replace("..*", ".*");
        if (!conditionString.startsWith("^") && !conditionString.startsWith(".*")) {
            conditionString = ".*" + conditionString;
        }
        if (!conditionString.endsWith("$") && !conditionString.endsWith(".*")) {
            conditionString += ".*";
        }
        return value.matches(conditionString);
    }
}
