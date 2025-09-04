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
package org.dependencytrack.util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * A class for assigning strings matched by regexes a certain priority specific to a ecosystem, e.g. ubuntu.
 */
public class Ecosystem {
    private String name;
    private final Integer equalToEmptyStringIndex;
    /**
     * The regex used for tokenizing the version string and assigning priorities to the tokens
     */
    private Pattern tokenRegex;
    /**
     * Constructor for a Ecosystem with three partial lists, each sorting from low priority to high priority
     *
     * @param preElements List with regexes with priorities lower than EndOfString
     * @param ignoreElement Regexes with priority same as EndOfString
     * @param postElements List with regexes with priorities higher than EndOfString
     */
    public Ecosystem(String name, List<String> preElements, String ignoreElement, List<String> postElements) {
        this.name = name;
        this.equalToEmptyStringIndex = preElements.size();

        List<String> elements = new ArrayList<>();
        elements.addAll(preElements);
        elements.add(ignoreElement);
        /* This acts as a splitter between two different version blocks which are compared separatly */
        elements.add("\n");
        elements.addAll(postElements);

        /* Make a matching group from each element and concate them with logical OR */
        String regexString = elements.stream().map(e -> "(" + e + ")").reduce((e1, e2) -> e1 + "|" + e2).orElse("");
        this.tokenRegex = Pattern.compile(regexString, Pattern.CASE_INSENSITIVE);
    }

    public String getName() {
        return name;
    }

    public Integer getEndOfStringPriority() {
        return equalToEmptyStringIndex;
    }

    public Pattern getTokenRegex() {
        return tokenRegex;
    }
}
