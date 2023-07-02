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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;

/**
 * A version distance consists of four parts for each of the difference in epoch,
 * major, minor or patch numbers between two versions.
 *
 * Each part is computed by calculating the difference of each number found in the
 * two versions. Since only the most significant part found is of any interest, only the
 * first difference found will be set, all others will be zero. This makes it easy to
 * compare two versions. For example the distence between 1.0.2 and 2.0.0 equals 1.0.0,
 * meaning the major number differs by one.
 *
 * Epoch is also support, so the distance will look like <epoch>:<major>.<minor>.<patch>:
 * <ul>
 *   <li>1:0.0.0/li>
 *   <li>0:1.0.0/li>
 *   <li>1:0.0.0/li>
 *   <li>0:0.3.0/li>
 *   <li>0:0.0.1/li>
 * </ul>
 * N.B. Optional build numbers, as fourtth number, are neglected
 *
 * VersionDistances can be compared to each other, but makes no sense to do math with
 * them: the difference between 1.6.0 and 1.2.3 is 0.4.0, but the sum of 1.6.0 and
 * 0.4.0 is not equal to 1.6.3.
 *
 * VersionDistances are absolute, negative distances are not allowed.
 *
 * @since 4.9.0
 */
public class VersionDistance implements Comparable<VersionDistance>,  Serializable {

    private static final long serialVersionUID = 1L;

    private static final String GROUP_EPOCH = "epoch";
    private static final String GROUP_MAJOR = "major";
    private static final String GROUP_MINOR = "minor";
    private static final String GROUP_PATCH = "patch";

    private static final Pattern DISTANCE_PATTERN = Pattern.compile(
        // Optional epoch part: numbers before the first : sign.
        "^(?:(?<"+GROUP_EPOCH+">\\d+):)?" +
        "(?<"+GROUP_MAJOR+">\\?|\\d+)"+
        "(?:\\.(?<"+GROUP_MINOR+">\\?|\\d+))?"+
        "(?:\\.(?<"+GROUP_PATCH+">\\?|\\d+))?"+
        "$"
    );

    // Semver-like version:any numbers parts without characters appended, with optial leading v.
    // Optionally appended with label and/or build metadata
    protected static final Pattern VERSION_PATTERN = Pattern.compile(
        "^(?:(?<"+GROUP_EPOCH+">.*):)?" + // Optional epoch part: number before the first : sign. Match any characters here so we can fail on incorrect values
        "v?(?<"+GROUP_MAJOR+">\\d+[a-z]*)?(?:\\.(?<"+GROUP_MINOR+">\\d+[a-z]*))?(?:\\.(?<"+GROUP_PATCH+">\\d+[a-z]*))?" + // version part, at least major version (numeric), optinali minor (numeric) or patch (numeric) version. Ignore the rest
        ".*$", // build numbers, labels and build metadata
        Pattern.CASE_INSENSITIVE
    );

    private int epoch;
    private int major;
    private int minor;
    private int patch;

    /**
     * Default all parts are set to 0
     */
    public VersionDistance() {
        this.epoch = 0;
        this.major = 0;
        this.minor = 0;
        this.patch = 0;
    }

    private void validate() throws IllegalArgumentException {
        if ((epoch != 0) && ((major >= 0) || (minor >= 0) || (patch >= 0))) {
            throw new IllegalArgumentException("Only the most significant number can be greater than 0, more significant parts cannot be ?");
        }
        if ((major != 0) && ((minor >= 0) || (patch >= 0))) {
            throw new IllegalArgumentException("Only the most significant number can be greater than 0, more significant parts cannot be ?");
        }
        if ((minor != 0) && (patch >= 0)) {
            throw new IllegalArgumentException("Only the most significant number can be greater than 0, more significant parts cannot be ?");
        }
    }

    public VersionDistance(int major, int minor, int patch) throws IllegalArgumentException {
        this (0, major, minor, patch);
    }

    public VersionDistance(int epoch, int major, int minor, int patch) throws IllegalArgumentException {
        this.epoch = epoch;
        this.major = major;
        this.minor = minor;
        this.patch = patch;
        validate ();
    }

    public VersionDistance(String distance) throws NumberFormatException, IllegalArgumentException {
        epoch = 0;
        major = 0;
        minor = 0;
        patch = 0;
        if (!StringUtils.isEmpty(distance)) {
            final var distanceMatcher = DISTANCE_PATTERN.matcher(distance);
            if (distanceMatcher.matches()) {
                epoch = parseVersion(distanceMatcher.group(GROUP_EPOCH));
                if (epoch == -1) {
                    epoch = 0;
                }
                major = parseVersion(distanceMatcher.group(GROUP_MAJOR));
                minor = parseVersion(distanceMatcher.group(GROUP_MINOR));
                if ((major != 0) && (distanceMatcher.group(GROUP_MINOR) == null)) {
                    minor = -1;
                }
                patch = parseVersion(distanceMatcher.group(GROUP_PATCH));
                if ((minor != 0) && (distanceMatcher.group(GROUP_PATCH) == null)) {
                    patch = -1;
                }
                validate();
            } else {
                throw new NumberFormatException("Invallid version distance: " + distance);
            }
        }
    }

    private static int parseVersion(String version) throws NumberFormatException {
        if (StringUtils.isEmpty(version)) {
            return 0;
        }
        if ("?".equals(version)) {
            return -1;
        }
        return Integer.parseInt(version);
    }

    /**
     * Parse a string of combined {@link VersionDistance}s and return tham as a {@link VersionDistance} {@link List}
     * @param combinedDistances combined version distance string, e.g 1:1.?.? -> (1:?.?.?, 0:1.?.?)
     * @return List of separate {@link VersionDistance}s
     * @throws NumberFormatException in case a version distance cannot be parsed
     */
    public static List<VersionDistance> parse(String combinedDistances) throws NumberFormatException {
        final List<VersionDistance> result = new ArrayList<VersionDistance>();
        final var distanceMatcher = DISTANCE_PATTERN.matcher(combinedDistances);
        if (distanceMatcher.matches()) {
            final var epoch = parseVersion(distanceMatcher.group(GROUP_EPOCH));
            if (epoch > 0) {
                result.add(new VersionDistance(epoch, -1, -1, -1));
            }
            final var major = parseVersion(distanceMatcher.group(GROUP_MAJOR));
            if (major > 0) {
                result.add(new VersionDistance(0, major, -1, -1));
            }
            final var minor = parseVersion(distanceMatcher.group(GROUP_MINOR));
            if (minor > 0) {
                result.add(new VersionDistance(0, 0, minor, -1));
            }
            final var patch = parseVersion(distanceMatcher.group(GROUP_PATCH));
            if (patch > 0) {
                result.add(new VersionDistance(0, 0, 0, patch));
            }
        } else {
            throw new NumberFormatException("Invallid version distance: " + combinedDistances);
        }
        return result;
    }

    public void setEpoch(int epoch) {
        this.epoch = epoch;
    }

    public int getEpoch() {
        return epoch;
    }

    public void setMajor(int major) {
        this.major = major;
    }

    public int getMajor() {
        return major;
    }

    public void setMinor(int minor) {
        this.minor = minor;
    }

    public int getMinor() {
        return minor;
    }

    public void setPatch(int patch) {
        this.patch = patch;
    }

    public int getPatch() {
        return patch;
    }

    private int compareEpoch(VersionDistance other) {
        return epoch - other.getEpoch();
    }

    private int compareMajor(VersionDistance other) {
        return major - other.getMajor();
    }

    private int compareMinor(VersionDistance other) {
        return minor - other.getMinor();
    }

    private int comparePatch(VersionDistance other) {
        return patch - other.getPatch();
    }

    @Override
    public boolean equals(Object o) {
        // self check
        if (this == o) {
            return true;
        }
        // null check
        if (o == null) {
            return false;
        }
        // type check and cast
        if (getClass() != o.getClass()) {
            return false;
        }
        VersionDistance versionDistance = (VersionDistance) o;
        // field comparison
        return versionDistance.getEpoch() == epoch && versionDistance.getMajor() == major && versionDistance.getMinor() == minor && versionDistance.getPatch() == patch;
    }

    @Override
    public int hashCode() {
        int result = 11 + epoch;
        result *= 17 + major;
        result *= 23 + minor;
        result *= 31 + patch;
        return result;
    }

    @Override
    public int compareTo(VersionDistance other) {
        final var epochDistance = compareEpoch(other);
        final var majorDistance = compareMajor(other);
        final var minorDistance = compareMinor(other);
        final var patchDistance = comparePatch(other);
        if (epochDistance != 0) {
            return epochDistance;
        }
        if (majorDistance != 0) {
            return majorDistance;
        }
        if (minorDistance != 0) {
            return minorDistance;
        }
        if (patchDistance != 0) {
            return patchDistance;
        }
        return 0;
    }

    @Override
    public String toString() {
        return epoch + ":" + (major < 0 ? "?" : major) + "." + (minor < 0 ? "?" : minor) + "." + (patch < 0 ? "?" : patch);
    }

    /**
     * Calculates the distance between two versions by calculating the absolute
     * difference in the epoch numbers, major version numbers, the minor version
     * numbers or the patch version numbers. When a number is not foud in the
     * version string, 0 is assumed.
     *
     * Only the first (most significant) difference number will be set, all
     * others will be 0. So the distance will look like <epoch>:<major>.<minor>.<patch>:
     * 1:?.?.?
     * 0:1.?.?
     * 1:?.?.?
     * 0:0.3.?
     * 0:0.0.1
     *
     * @param version1 the first version
     * @param version2 the second version
     *
     * @return VersionDistance distance between version1 and version2
     */
    public static VersionDistance getVersionDistance(String version1, String version2) {
        if (version1 == null) {
            version1 = "";
        }
        if (version2 == null) {
            version2 = "";
        }
        final var v1matcher = VERSION_PATTERN.matcher(version1);
        final var v2matcher = VERSION_PATTERN.matcher(version2);
        if (v1matcher.matches() && v2matcher.matches()) {
            // version1
            final var epoch1 = VersionDistance.parseVersion(v1matcher.group(GROUP_EPOCH));
            final var major1 = VersionDistance.parseVersion(v1matcher.group(GROUP_MAJOR));
            final var minor1 = VersionDistance.parseVersion(v1matcher.group(GROUP_MINOR));
            final var patch1 = VersionDistance.parseVersion(v1matcher.group(GROUP_PATCH));
            // version2
            final var epoch2 = VersionDistance.parseVersion(v2matcher.group(GROUP_EPOCH));
            final var major2 = VersionDistance.parseVersion(v2matcher.group(GROUP_MAJOR));
            final var minor2 = VersionDistance.parseVersion(v2matcher.group(GROUP_MINOR));
            final var patch2 = VersionDistance.parseVersion(v2matcher.group(GROUP_PATCH));

            final var epochDistance = Math.abs(epoch2 - epoch1);
            final var majorDistance = Math.abs(major2 - major1);
            final var minorDistance = Math.abs(minor2 - minor1);
            final var patchDistance = Math.abs(patch2 - patch1);
            if (epochDistance != 0) {
                return new VersionDistance(epochDistance, -1, -1, -1);
            }
            if (majorDistance != 0) {
                return new VersionDistance(0, majorDistance, -1, -1);
            }
            if (minorDistance != 0) {
                return new VersionDistance(0, 0, minorDistance, -1);
            }
            if (patchDistance != 0) {
                return new VersionDistance(0, 0, 0, patchDistance);
            }
            return new VersionDistance(0, 0, 0, 0);
        }
        throw new NumberFormatException("Incompatible versions: " + version1 + ", " + version2);
    }

}