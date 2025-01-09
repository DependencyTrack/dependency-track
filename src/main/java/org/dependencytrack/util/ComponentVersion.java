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
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.concurrent.NotThreadSafe;

//import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;

/**
 * <p>
 * Simple object to track the parts of a version number. The parts are contained
 * in a List such that version 1.2.3 will be stored as:  <code>versionParts[0] = 1;
 * versionParts[1] = 2;
 * versionParts[2] = 3;
 * </code></p>
 * <p>
 * Note, the parser contained in this class expects the version numbers to be
 * separated by periods. If a different separator is used the parser will likely
 * fail.</p>
 *
 * @author Jeremy Long
 *
 * Ported from DependencyVersion in Dependency-Check v5.2.1
 */
@NotThreadSafe
public class ComponentVersion implements Iterable<String>, Comparable<ComponentVersion> {
    /**
     * A class for describing a version part or a separator.
     */
    private class Token {
        /**
         * An integer describing the sort order, the main sort criterion
         */
        private Integer priority;
        /**
         * A string holding a actual value, the secondary sort criterion
         */
        private String value;

        public Token(Integer priority, String value) {
            this.priority = priority;
            this.value = value;
        }

        public Integer getPriority() {
            return priority;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * A class for assigning strings matched by regexes a certain priority specific to a ecosystem, e.g. ubuntu.
     */
    private class Ecosystem {
        private String name;
        private final Integer equalToEmptyStringIndex;
        /**
         * The list of regexs, sorting from low priority to high priority
         */
        private List<String> elements;
        /**
         * Constructor for a Ecosystem with three partial lists, each sorting from low priority to high priority
         *
         * @param pre_elements List with regexes with priorities lower than EndOfString
         * @param ignore_elements List with regexes with priorities same as EndOfString
         * @param post_elements List with regexes with priorities higher than EndOfString
         */
        public Ecosystem(String name, List<String> pre_elements, List<String> ignore_elements, List<String> post_elements) {
            this.name = name;
            this.equalToEmptyStringIndex = pre_elements.size();
            this.elements = new ArrayList<>();
            this.elements.addAll(pre_elements);
            this.elements.addAll(ignore_elements);
            /* This acts as a splitter between two different version blocks which are compared separatly */
            this.elements.add("\n");
            this.elements.addAll(post_elements);
        }

        public String getName() {
            return name;
        }

        public Integer getEndOfStringPriority() {
            return equalToEmptyStringIndex;
        }

        public List<String> getElements() {
            return elements;
        }
    }

    /**
     * A list of the version parts.
     */
    private List<Token> versionParts;

    /**
     * Member holding to with ecosystem this version belongs to.
     */
    private Ecosystem ecosystem;

    /**
     * Constructor for a empty DependencyVersion.
     */
    public ComponentVersion() {
        /* TODO: Do not create for every instance an own object. Generate once and reference it then */
        /* TODO: The selected Ecosystem should be depedent on the purl. if there is no purl default to semver */
        this.ecosystem = new Ecosystem("deb", List.of("~"), List.of("#"), List.of("\\d+", "[a-z]+", "\\+", "-", "\\.", ":"));
    }

    /**
     * Constructor for a DependencyVersion that will parse a version string.
     * <b>Note</b>, this should only be used when the version passed in is
     * already known to be a well formatted version number. Otherwise,
     * DependencyVersionUtil.parseVersion() should be used instead.
     *
     * @param version the well formatted version number to parse
     */
    public ComponentVersion(String version) {
        /* TODO: Do not create for every instance an own object. Generate once and reference it then */
        /* TODO: The selected Ecosystem should be depedent on the purl. if there is no purl default to semver */
        this.ecosystem = new Ecosystem("deb", List.of("~"), List.of("#"), List.of("\\d+", "[a-z]+", "\\+", "-", "\\.", ":"));
        parseVersion(version);
    }

    /**
     * Parses a version string into its sub parts: major, minor, revision,
     * build, etc. <b>Note</b>, this should only be used to parse something that
     * is already known to be a version number.
     *
     * @param version the version string to parse
     */
    public final void parseVersion(String version) {
        versionParts = new ArrayList<>();
        String regex = this.ecosystem.getElements().stream().map(e -> "(" + e + ")").reduce((e1, e2) -> e1 + "|" + e2).orElse("");
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);

        if(version == null) {
            return;
        }

        // Debian/Ubuntu specific
        if(this.ecosystem.name=="deb") {
            // When no epoch is given, use default epoch 0
            if (!version.contains(":")) {
               version = "0:" + version;
            }

           // So we replace '-' which acts a blocks splitter (split between upstream and debian version) by the block-splitter "\n" since
           // also upstream versions uses sometimes '-'. But to follow semver with debian sorting it should be debian pre-splitter '~'
           int debianSplitterIndex = version.lastIndexOf("-");
           if(debianSplitterIndex > 0) {
               version = version.substring(0, debianSplitterIndex) + "\n" + version.substring(debianSplitterIndex + 1);
           }
        }

        // General part
        Matcher matcher = pattern.matcher(version.toLowerCase());
        while (matcher.find()) {
            for (int i = 1; i <= this.ecosystem.getElements().size(); i++) {
                if (matcher.group(i) != null) {
                    versionParts.add(new Token(i - 1, matcher.group(i)));
                    break;
                }
            }
        }
    }

    /**
     * Get the value of versionParts.
     *
     * @return the value of versionParts
     */
    public List<Token> getVersionParts() {
        return versionParts;
    }

    /**
     * Set the value of versionParts.
     *
     * @param versionParts new value of versionParts
     */
    public void setVersionParts(List<Token> versionParts) {
        this.versionParts = versionParts;
    }

    /**
     * Retrieves an iterator for the version parts.
     *
     * @return an iterator for the version parts
     */
    @Override
    public Iterator<Token> iterator() {
        return versionParts.iterator();
    }

    /**
     * Reconstructs the version string from the split version parts.
     *
     * @return a string representing the version.
     */
    @Override
    public String toString() {
        StringBuilder result = new StringBuilder();
        for (Token token : this.versionParts) {
            result.append(token.getValue());
        }
        return result.toString();
    }

    /**
     * Compares the equality of this object to the one passed in as a parameter.
     *
     * @param obj the object to compare equality
     * @return returns true only if the two objects are equal, otherwise false
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof ComponentVersion)) {
            return false;
        }
        return (compareTo((ComponentVersion) obj) == 0);
    }

    /**
     * Calculates the hashCode for this object.
     *
     * @return the hashCode
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(5, 71)
                .append(versionParts)
                .toHashCode();
    }

    /**
     * Determines if the three most major major version parts are identical. For
     * instances, if version 1.2.3.4 was compared to 1.2.3 this function would
     * return true.
     *
     * @param version the version number to compare
     * @return true if the first three major parts of the version are identical
     */
    @Override
    public int compareTo(ComponentVersion version) {
        if (version == null) {
            return 1;
        }
        final List<String> left = this.getVersionParts();
        final List<String> right = version.getVersionParts();
        final int max = left.size() < right.size() ? left.size() : right.size();

        for (int i = 0; i < max; i++) {
            final String lStr = left.get(i);
            final String rStr = right.get(i);
            if (lStr.equals(rStr)) {
                continue;
            }
            try {
                final int l = Integer.parseInt(lStr);
                final int r = Integer.parseInt(rStr);
                if (l < r) {
                    return -1;
                } else if (l > r) {
                    return 1;
                }
            } catch (NumberFormatException ex) {
                final int comp = left.get(i).compareTo(right.get(i));
                if (comp < 0) {
                    return -1;
                } else if (comp > 0) {
                    return 1;
                }
            }
        }
        // Modified from original by Steve Springett
        // Account for comparisons where one version may be 1.0.0 and another may be 1.0.0.0.
        if (left.size() == max && right.size() == left.size()+1 && right.get(right.size()-1).equals("0")) {
            return 0;
        } else if (right.size() == max && left.size() == right.size()+1 && left.get(left.size()-1).equals("0")) {
            return 0;
        } else {
            return Integer.compare(left.size(), right.size());
        }
    }
}
