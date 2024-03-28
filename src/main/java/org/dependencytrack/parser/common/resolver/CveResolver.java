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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.parser.common.resolver;

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import org.apache.commons.lang3.StringUtils;
/**
 * Attempts to obtain a valid CVE ID from a string
 */
public class CveResolver {

    private static final CveResolver INSTANCE = new CveResolver();

    private CveResolver() {
    }

    public static CveResolver getInstance() {
        return INSTANCE;
    }

    /**
     * Returns a valid CVE ID if found in the input string, or null otherwise
     * If the input string is not a valid CVE ID, attempts to add "CVE-" prefix before checking again
     * Returns null if the input string is empty, null or do not match.
     *
     * @param cveString the input string, potentially containing a CVE ID
     * @return the valid CVE ID
     */
    public String getValidCveId(String cveString) {
        if (StringUtils.isNotBlank(cveString)) {
            // Define the regex pattern
            String pattern = "^CVE-\\d{4}-\\d+$";
            // Compile the pattern
            Pattern regex = Pattern.compile(pattern);
            if (!cveString.startsWith("CVE-")){
                // Try adding "CVE-" to the beginning of cveString
                cveString = "CVE-" + cveString;
            }
            // Match the input against the pattern
            Matcher matcher = regex.matcher(cveString);
            if (matcher.matches()) {
                return cveString;
            }
        }
        return null;
    }
}
