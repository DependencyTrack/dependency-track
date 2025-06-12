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

import alpine.common.logging.Logger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;

import javax.annotation.concurrent.NotThreadSafe;

import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.builder.HashCodeBuilder;

/**
 * <p>
 * Simple object to track the parts of a version number. The parts are contained
 * in a List such that version 1.2.3 will be stored as:  <code>
 * versionParts[0] = new Token(PRIOITY_OF_STRING, "1");
 * versionParts[1] = new Token(PRIORITY_OF_DOT, ".");
 * versionParts[2] = new Token(PRIORITY_OF_STRING, "2");
 * versionParts[3] = new Token(PRIORITY_OF_DOT, ".");
 * versionParts[4] = new Token(PRIORITY_OF_STRING, "3");
 * </code></p>
 *
 * @author Andre Wagner
 *
 */
@NotThreadSafe
public class ComponentVersion implements Comparable<ComponentVersion> {
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
        this.ecosystem = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.GENERIC);
    }

    public ComponentVersion(Ecosystem ecosystem) {
        this.ecosystem = ecosystem;
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
        this.ecosystem = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.GENERIC);
        parseVersion(version);
    }

    public ComponentVersion(Ecosystem ecosystem, String version) {
        this.ecosystem = ecosystem;
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

        if(version == null) {
            return;
        }

        // Debian/Ubuntu specific
        if(this.ecosystem.getName().equals("deb")) {
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
        Matcher matcher = this.ecosystem.getTokenRegex().matcher(version.toLowerCase());
        while (matcher.find()) {
            for (int i = 1; i <= matcher.groupCount(); i++) {
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
    private List<Token> getVersionParts() {
        return versionParts;
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
            result.append(token.getValue().replaceAll("\n","-"));
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

    @Override
    public int compareTo(ComponentVersion version) {
        if (version == null) {
            return 1;
        }

        if(!this.ecosystem.getName().equals(version.ecosystem.getName())) {
            Logger.getLogger(getClass()).warn("Comparing versions of ecosystem %s and ecosystem %s: This will led to wrong results"
                    .formatted(this.ecosystem.getName(), version.ecosystem.getName()));

        }

        int resultCode = 0;

        Iterator<Token> version1Iterator = this.getVersionParts().iterator();
        Iterator<Token> version2Iterator = version.getVersionParts().iterator();

        Token version1Field;
        Token version2Field;

        while(true) {
            version1Field = version1Iterator.hasNext() ? version1Iterator.next() : null;
            version2Field = version2Iterator.hasNext() ? version2Iterator.next() : null;


            Integer priority1 = (version1Field != null) ? version1Field.getPriority() : this.ecosystem.getEndOfStringPriority();
            Integer priority2 = (version2Field != null) ? version2Field.getPriority() : this.ecosystem.getEndOfStringPriority();

            if((resultCode = Integer.compare(priority1, priority2)) != 0) {
                break;
            }


            if (version1Field == null || version2Field == null) {
                break;
            }

            String value1 = version1Field.getValue();
            String value2 = version2Field.getValue();

            if(Character.isDigit(value1.charAt(0)) && Character.isDigit(value2.charAt(0))) {
                if(value1.length() > value2.length()) {
                    value2 = "0".repeat(value1.length() - value2.length()) + value2;
                }
                else if(value1.length() < value2.length()) {
                    value1 = "0".repeat(value2.length() - value1.length()) + value1;
                }
            }

            if((resultCode = value1.compareTo(value2)) != 0) {
                break;
            }
        }

        return resultCode;
    }

    /**
     * Reflects if there is a version contained.
     *
     * @return true if there is.
     */
    public boolean isEmpty() {
        return versionParts == null || versionParts.isEmpty();
    }
}
