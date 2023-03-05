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
package org.dependencytrack.util;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.maven.artifact.versioning.ComparableVersion;

import com.vdurmont.semver4j.Semver;

public class ComponentVersion implements Comparable<ComponentVersion> {

    // Optional epoch part: number before the first : sign
    protected static final String EPOCH_PATTERN_STRING = "^(?:(?<epoch>\\d*):)?";

    // Optional label: everything after a ~, ^ or - sign, or after a . sign when it doesn't start with a number
    protected static final String LABEL_PATTERN_STRING = "(?<label>[-~^].*?|\\.[a-z].*?)?";

    // Optional build metadata: everyhing after the last + sign:
    protected static final String BUILD_METADATA_PATTERN_STRING = "(?:\\+.*)?";

    // Non-semver version:any numbers parts optionally appended with characters
    // or numbers separated by dots (max 5 groups), with optial leading v.
    // Optionally appended with label and/or build metadata
    protected static final Pattern NONSEMVER_VERSIONS_PATTERN = Pattern.compile(
        EPOCH_PATTERN_STRING + // epoch
        "(?<version>v?\\d+[a-z0-9]*(?:\\.\\d+[a-z0-9]*){0,5})" + // version part
        LABEL_PATTERN_STRING + // label part
        BUILD_METADATA_PATTERN_STRING + "$", // build metadata part
        Pattern.CASE_INSENSITIVE
        );


    // Ubuntu version format:
    // https://wiki.ubuntu.com/AutoStatic/PackagingVersioningScheme
    // https://docs.fedoraproject.org/en-US/packaging-guidelines/Versioning/
    // anything containing "ubuntu" or "ppa" is considered a debian version
    protected static final String PPA_PATTER_STRING = "(?:ppa(\\d.*))"; // needs group wrap since ? might be appended!
                                                                        // unable to name the group since pattern is used multiple times
    protected static final String UBUNTU_PATTERN_STRING = "ubuntu(?<os>\\d.*?)";
    protected static final Pattern UBUNTU_RELEASE_PATTERN = Pattern.compile(
        EPOCH_PATTERN_STRING +
        "(?<version>.*?)" + // version part, many variations here...
        "(?:" +
        UBUNTU_PATTERN_STRING + PPA_PATTER_STRING + "?" + // ubuntu version + optional ppa version
        "|" + PPA_PATTER_STRING + // ppa version only
        ")" + LABEL_PATTERN_STRING + BUILD_METADATA_PATTERN_STRING + "$",
        Pattern.CASE_INSENSITIVE
    );

    // Debian version format:
    // https://www.debian.org/doc/manuals/developers-reference/pkgs.html
    // https://blog.jasonantman.com/2014/07/how-yum-and-rpm-compare-versions/
    // anything containing "deb", "dfsg" or "ds" is considered a debian version
    private static final String DEBIAN_PATTERN_STRING = "(?:\\+deb(?<os>\\d+(?:u\\d+)?))";
    private static final String DFSG_PATTERN_STRING = "(?:[\\+-](?:dfsg|ds)[\\.-]?(\\d*-?\\d*))"; // needs group wraps since ? might be appended!
                                                                                                  // unable to name the group, since pattern is used multiple times
    protected static final Pattern DEBIAN_RELEASE_PATTERN = Pattern.compile(
        EPOCH_PATTERN_STRING +
        "(?<version>.*?)" + // version part, many variations here...
        "(?:" +
        "(?:" + DFSG_PATTERN_STRING + ")?" + DEBIAN_PATTERN_STRING + // debian release + optional DFSG part
        "|" + DFSG_PATTERN_STRING + // DFSG part only
        ")" + LABEL_PATTERN_STRING + BUILD_METADATA_PATTERN_STRING + "$",
        Pattern.CASE_INSENSITIVE
        );

    // Semver version format:
    // https://semver.org/
    // restricted number, label and build metadata parts to preven ReDOS attacks.
    protected static final Pattern SEMVER_PATTERN = Pattern.compile("^(0|[1-9]\\d{0,32})\\.(0|[1-9]\\d{0,32})\\.(0|[1-9]\\d{0,32})(?:-((?:0|[1-9]\\d{0,32}|\\d{0,32}[a-zA-Z-][0-9a-zA-Z-]{0,100})(?:\\.(?:0|[1-9]\\d{0,32}|\\d{0,32}[a-zA-Z-][0-9a-zA-Z-]{0,100})){0,8}))?(?:\\+([0-9a-zA-Z-]{1,100}(?:\\.[0-9a-zA-Z-]{1,100}){0,8}))?$");

    protected static final Pattern SEMVER_PRE_RELEASE_PATTERN = Pattern.compile("(-[0-9a-z]).*", Pattern.CASE_INSENSITIVE);

    // Well-known labels denoting unstable versions
    protected static final Pattern UNSTABLE_LABELS_PATTERN = Pattern.compile("[\\.-](dev|atlassian|preview|next|canary|snapshot|a|alpha|b|beta|rc|cr|m|mr|ea).*", Pattern.CASE_INSENSITIVE);

    /**
     * Parse two version strings  and compare the versions using {@link ComponentVersion}
     *
     * @param v1string first version to compare
     * @param v2string second version to compare
     * @return 0 when the versions are equal, > 0 if v2 is larger than v1, < 0 when v2 is smaler than v1
     * @see ComponentVersion#compareTo
     */
    public static int compareVersions(String v1string, String v2string) {
        ComponentVersion v1 = new ComponentVersion(v1string);
        ComponentVersion v2 = new ComponentVersion(v2string);
        return v1.compareTo(v2);
    }

    /**
     * Parse two version strings and return the one containing the highest version
     *
     * @param v1string first version to compare
     * @param v2string second version to compare
     * @return the highest of two versions as string value
     */
    public static String highestVersion(String v1string, String v2string) {
        return ComponentVersion.compareVersions(v1string, v2string) > 0 ? v1string : v2string;
    }

    /**
     * Determine wether a version string denotes a SemVer version
     *
     * @param version the version string
     * @return true if the version string denotes a SemVer version
     */
    public static boolean isSemver(String version) {
        return SEMVER_PATTERN.matcher(version).matches();
    }

    /**
     * Determine wether a version string denotes a stable version
     *
     * @param version the version string
     * @return true if the version string denotes a stable version
     */
    public static boolean isStableVersion(String version) {
        final var ubuntuMatcher = UBUNTU_RELEASE_PATTERN.matcher(version);
        if (ubuntuMatcher.matches()) {
            return true; // could this be false? how?
        }

        final var debianMatcher = DEBIAN_RELEASE_PATTERN.matcher(version);
        if (debianMatcher.matches()) {
            return true; // could this be false? how?
        }

        if (ComponentVersion.isSemver(version)) {
            return new Semver(version).isStable();
        }

        Matcher versionMatcher = NONSEMVER_VERSIONS_PATTERN.matcher(version);
        if (versionMatcher.matches()) {
            String label = versionMatcher.group("label");
            return !ComponentVersion.isUnstableLabel(label);
        } else {
            return false;
        }
    }

    private static boolean isUnstableLabel(String label) {
        return label != null && (SEMVER_PRE_RELEASE_PATTERN.matcher(label).matches() || UNSTABLE_LABELS_PATTERN.matcher(label).matches());

    }

    /**
     * Get the highest version from a list of version strings
     *
     * @param versions list of version strings
     * @return the highest version in the list
     */
    public static String findHighestStableOrUnstableVersion(List<String> versions) {
        String highestStableOrUnstableVersion = null;
        if (!versions.isEmpty()) {
            highestStableOrUnstableVersion = versions.stream().reduce(null, ComponentVersion::highestVersion);
        }
        return highestStableOrUnstableVersion;
    }

    /**
     * Get the highest stable version from a list of version strings
     *
     * @param versions list of version strings
     * @return the highest version in the list
     */
    public static String findHighestStableVersion(List<String> versions) {
        // collect stable versions
        List<String> stableVersions = versions.stream().filter(ComponentVersion::isStableVersion).toList();
        return findHighestStableOrUnstableVersion(stableVersions);
    }


    /**
     * Get the highest  version from a list of version strings. When a stable version is found
     * this is returned, otherwise an unstable version or null weh no version is found
     *
     * @param versions list of version strings
     * @return the highest version in the list
     */
    public static String findHighestVersion(List<String> versions) {
        // find highest stable version from list of versions
        String highestStableOrUnstableVersion = ComponentVersion.findHighestStableOrUnstableVersion(versions);

        if (highestStableOrUnstableVersion != null && ComponentVersion.isStableVersion(highestStableOrUnstableVersion)) {
            return highestStableOrUnstableVersion;
        } else {
            // find highest stable version
            String highestStableVersion = findHighestStableVersion(versions);

            // use highestStableVersion, or else latest unstable release (e.g. alpha, milestone) or else latest snapshot
            return highestStableVersion != null ? highestStableVersion: highestStableOrUnstableVersion;
        }
    }

    /**
     * The version string
     */
    private String version;

    /**
     * Constructor for a empty DependencyVersion.
     */
    public ComponentVersion() {
    }

    /**
     * Constructor for a DependencyVersion that will parse a version string.
     *
     * @param version the version number to parse
     */
    public ComponentVersion(String version) {
        this.version = version;
    }

    public String getVersion() {
        return this.version;
    }

    /**
     * Reconstructs the version string from the split version parts.
     *
     * @return a string representing the version.
     */
    @Override
    public String toString() {
        return version;
    }

    /**
     * Compares the equality of this object to the one passed in as a parameter.
     *
     * @param obj the object to compare equality
     * @return returns true only if the two objects are equal, otherwise false
     */
    @Override
    public boolean equals(Object obj) {
        // self check
        if (this == obj)
            return true;
        // null check
        if (obj == null)
            return false;
        // type check and cast
        if (getClass() != obj.getClass())
            return false;

        return version.equals(((ComponentVersion)obj).getVersion());
    }

    /**
     * Calculates the hashCode for this object.
     *
     * @return the hashCode
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(5, 71)
                .append(version)
                .toHashCode();
    }

    @Override
    public int compareTo(ComponentVersion version) {
        if (version == null || version.getVersion() == null || "".equals(version.getVersion())) {
            if (this.getVersion() == null || "".equals(this.getVersion())) {
                return 0;
            }
            return 1;
        }
        if (this.getVersion() == null || "".equals(this.getVersion())) {
            return -1;
        }
        final var v1string = getVersion();
        final var v2string = version.getVersion();
        final var v1UbuntuMatcher = UBUNTU_RELEASE_PATTERN.matcher(v1string);
        final var v2UbuntuMatcher = UBUNTU_RELEASE_PATTERN.matcher(v2string);
        if (v1UbuntuMatcher.matches() || v2UbuntuMatcher.matches()) {
            return compareUbuntuVersions(v1string, v2string, v1UbuntuMatcher, v2UbuntuMatcher);
        }

        final var v1DebianMatcher = DEBIAN_RELEASE_PATTERN.matcher(v1string);
        final var v2DebianMatcher = DEBIAN_RELEASE_PATTERN.matcher(v2string);
        if (v1DebianMatcher.matches() || v2DebianMatcher.matches()) {
            return compareDebianVersions(v1DebianMatcher, v2DebianMatcher);
        }

        if (ComponentVersion.isSemver(v1string) && ComponentVersion.isSemver(v2string)) {
            return compareSemver(v1string, v2string);
        }
        return compareNonSemverVersions(stripLeadingV(v1string), stripLeadingV(v2string));
    }

    private int compareDebianVersions(final String v1string, final String v2string) {
        final var v1DebianMatcher = DEBIAN_RELEASE_PATTERN.matcher(v1string);
        final var v2DebianMatcher = DEBIAN_RELEASE_PATTERN.matcher(v2string);
        if (v1DebianMatcher.matches() || v2DebianMatcher.matches()) {
            return compareDebianVersions(v1DebianMatcher, v2DebianMatcher);
        }
        if (ComponentVersion.isSemver(v1string) && ComponentVersion.isSemver(v2string)) {
            return compareSemver(v1string, v2string);
        }
        return compareNonSemverVersions(v1string, v2string);
    }

    private int compareDebianVersions(final Matcher v1matcher, final Matcher v2matcher) {
        // compare epoch part
        final var epoch1 = getEpoch(v1matcher);
        final var epoch2 = getEpoch(v2matcher);

        final var epochCompare = Integer.compare(Integer.parseInt(epoch1),Integer.parseInt(epoch2));
        if (epochCompare == 0) {
            final var version1 = v1matcher.matches() ? v1matcher.group("version") : null;
            final var version2 = v2matcher.matches() ? v2matcher.group("version") : null;
            if (version1 == null) {
                return -1; // 1debian > 1
            }
            if (version2 == null) {
                return 1; // 1 < 1debian
            }
            final var versionCompare = compareNonSemverVersions(version1, version2);
            if (versionCompare == 0) {
                // compare os version
                final String osVersion1 = v1matcher.group("os");
                final String osVersion2 = v2matcher.group("os");

                final var osVersionCompare = compareNonSemverVersions(osVersion1, osVersion2);
                if (osVersionCompare == 0 ) {
                    // compare DFSG
                    final String dfsg1 = v1matcher.matches() ? getDFSG(v1matcher) : null;
                    final String dfsg2 = v2matcher.matches() ? getDFSG(v2matcher) : null;
                    if (dfsg1 == null) {
                        if (dfsg2 == null) {
                            return 0;
                        }
                        return 1; // 1ppa > 1
                    }
                    if (dfsg2 == null) {
                        return -1; // 1 < 1ppa
                    }
                    return new ComparableVersion(dfsg1).compareTo(new ComparableVersion(dfsg2));
                } else {
                    return osVersionCompare;
                }

            }

            return versionCompare;
        }
        return epochCompare;
    }

    private String getEpoch(final Matcher v1matcher) {
        final var epoch1 = v1matcher.matches() && v1matcher.group("epoch") != null ? v1matcher.group("epoch") : "0";
        return epoch1;
    }

    private String getDFSG(Matcher matcher) {
        final var group3 = matcher.group(3);
        final var group5 = matcher.group(5);
        return group5 != null ? group5 : group3;
    }

    private int compareUbuntuVersions(final String v1string, final String v2string, final Matcher v1matcher,
            final Matcher v2matcher) {
        final var epoch1 = getEpoch(v1matcher);
        final var epoch2 = getEpoch(v2matcher);

        final var epochCompare = Integer.compare(Integer.parseInt(epoch1),Integer.parseInt(epoch2));
        if (epochCompare == 0) {
            // https://wiki.ubuntu.com/AutoStatic/PackagingVersioningScheme
            final var debianVersion1 = v1matcher.matches() ? v1matcher.group("version") : v1string;
            final var debianVersion2 = v2matcher.matches() ? v2matcher.group("version") : v2string;
            final var debianVersionCompare = compareDebianVersions(debianVersion1, debianVersion2);
            if (debianVersionCompare == 0) {
                // compare os versions
                final var osVersion1 = v1matcher.matches() ? v1matcher.group("os") : null;
                final var osVersion2 = v2matcher.matches() ? v2matcher.group("os") : null;
                if (osVersion1 == null && osVersion2 == null) {
                    return comparePPA(v1matcher, v2matcher);
                }
                if (osVersion1 == null) {
                    return -1; // 1ubuntu > 1
                }
                if (osVersion2 == null) {
                    return 1; // 1 < 1ubuntu
                }
                final var osVersionCopare = new ComparableVersion(osVersion1).compareTo(new ComparableVersion(osVersion2));
                if (osVersionCopare == 0) {
                    return comparePPA(v1matcher, v2matcher);
                }
                // different ubuntu versions might be incompatible, but this is
                // not taken in consideration here
                return osVersionCopare;
            }
            return debianVersionCompare;
        }
        return epochCompare;
    }

    private int compareSemver(String version1, String version2) {
        // Defaults to STRICT mode
        Semver semver1 = new Semver(version1);
        Semver semver2 = new Semver(version2);
        return semver1.compareTo(semver2);
    }

    /**
     * Compare two non-semver version strings using {@link ComparableVersion}. First
     * compare the version parts, since {@link ComparableVersion} not alwasy returns correct
     * results (for example 1.0.10b-1 < 1.0.10-1). Only compare the version labels when
     * the version parts are equal.
     *
     * @param version1 first version to compare
     * @param version2 second version to compare
     * @return < 0 if version1 is the lowest, > 0 when version1 is the highest, 0 when equal.
     * @see ComparableVersion#compareTo
     */
    private int compareNonSemverVersions(String version1, String version2) {
        if ((version1 == null) && (version2 == null)) {
            return 0;
        }
        if ((version1 != null) && version1.equals(version2)) {
            return 0;
        }
        if (version1 == null) {
            return 1;
        }
        if (version2 == null) {
            return -1;
        }

        Matcher v1matcher = NONSEMVER_VERSIONS_PATTERN.matcher(version1);
        Matcher v2matcher = NONSEMVER_VERSIONS_PATTERN.matcher(version2);

        if (v1matcher.matches() && v2matcher.matches()) {
            // compare epoch part
            final var epoch1 = v1matcher.matches() && v1matcher.group("epoch") != null ? v1matcher.group("epoch") : "0";
            final var epoch2 = v2matcher.matches() && v2matcher.group("epoch") != null ? v2matcher.group("epoch") : "0";

            final var epochCompare = Integer.compare(Integer.parseInt(epoch1),Integer.parseInt(epoch2));
            if (epochCompare == 0) {
                final var v1 = v1matcher.group("version");
                final var v2 = v2matcher.group("version");
                final var versionCompare = new ComparableVersion(v1).compareTo(new ComparableVersion(v2));
                if (versionCompare == 0) {
                    final var v1label = v1matcher.group("label");
                    final var v2label = v2matcher.group("label");
                    return compareVersionLabels(v1label, v2label);
                }
                return versionCompare;
            }
            return epochCompare;
        }
        // unrecofnised versions, fallback to ComparableVersion
        return new ComparableVersion(stripLeadingV(version1)).compareTo(new ComparableVersion(stripLeadingV(version2)));
    }

    /**
     * Compare two version labels by creating dummy versions and
     * comparing those using {@link ComparableVersion}
     *
     * @param label1 first label to compare
     * @param label2 second label to compare
     * @return < 0 if label1 is the lowest, > 0 when label1 is the highest, 0 when equal.
     * @see ComparableVersion#compareTo
     */
    private int compareVersionLabels(String label1, String label2) {
        if ((label1 == null) && (label2 == null)) {
            return 0;
        }
        if ((label1 != null) && label1.equals(label2)) {
            return 0;
        }
        if (label1 == null) {
            if (!label2.startsWith(".") && (label2.startsWith("~") || isUnstableLabel(label2))) {
                // 1 > 1-rc1
                // 1 > 1-alpha
                // 1 > 1-snapshot
                // 1 > 1~earlier
                return 1;
            }
            // 1 < 1^later
            // 1 < 1-something
            return -1;
        }
        if (label2 == null) {
            if (!label1.startsWith(".") && (label1.startsWith("~") || isUnstableLabel(label1))) {
                // 1-alpha < 1
                // 1-snapshot < 1
                // 1~earlier < 1
                return -1;
            }
            // 1.next > 1
            // 1^later > 1
            // 1-something > 1
            return 1;
        }
        if (
            (label1.startsWith("~") && !label2.startsWith("~")) ||
            (label2.startsWith("^") && !label1.startsWith("^"))
        ) {
            // sort earlier
            return -1;
        }

        if (
            (label1.startsWith("^") && !label2.startsWith("^")) ||
            (label2.startsWith("~") && !label1.startsWith("~"))
        ) {
            // sort later
            return 1;
        }
        return new ComparableVersion("1" + label1).compareTo(new ComparableVersion("1" + label2));
    }

    /**
     * Compare PPA parts of two versions using {@link ComparableVersion}
     *
     * @param v1matcher regex matcher for first version
     * @param v2matcher regex matcher for second version
     *
     * @return < 0 if label1 is the lowest, > 0 when label1 is the highest, 0 when equal.
     * @see ComparableVersion#compareTo
     */
    private int comparePPA(final Matcher v1matcher, final Matcher v2matcher) {
        // compare ppa
        final String ppa1 = v1matcher.matches() ? getPPA(v1matcher) : null;
        final String ppa2 = v2matcher.matches() ? getPPA(v2matcher) : null;
        if (ppa1 == null) {
            if (ppa2 == null) {
                return 0;
            }
            return -1; // 1 < 1ppa1
        }
        if (ppa2 == null) {
            return 1; // 1ppa1 > 1
        }
        return new ComparableVersion(ppa1).compareTo(new ComparableVersion(ppa2));
    }

    /**
     * Extract PPA part of a version. Depending of the version string, this
     * might be group 5 or group 4
     *
     * @param matcher regex matcher for the version
     * @return group 5 or group 4, when group 5 is 0
     */
    private String getPPA(Matcher matcher) {
        final var group4 = matcher.group(4);
        final var group5 = matcher.group(5);
        return group5 != null ? group5 : group4;
    }

    /**
     * remove the 'v' sign when a version string starts with it
     * @param version  version string
     * @return version withoud leading 'v'
     */
    protected static String stripLeadingV(String version) {
        if (version == null) {
            return null;
        }
        return version.toLowerCase().startsWith("v") ? version.substring(1) : version;
    }

}
