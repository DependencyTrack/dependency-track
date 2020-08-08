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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Component;

/**
 * A collection of utilities that compare the identity of a component.
 *
 * @since 4.0.0
 */
public class ComponentIdentificationUtil {

    private ComponentIdentificationUtil() { }

    @SuppressWarnings("deprecation")
    public static boolean doesIdentityMatch(final Component a, final org.cyclonedx.model.Component b) {
        if (a == null || b == null) {
            return false;
        }
        if (isMatch(a.getPurl(), b.getPurl())) {
            return true;
        }
        if (isMatch(a.getPurlCoordinates(), b.getPurl())) {
            return true;
        }
        if (b.getSwid() != null && isMatch(a.getSwidTagId(), b.getSwid().getTagId())) {
            return true;
        }
        if (isMatch(a.getCpe(), b.getCpe())) {
            return true;
        }
        if (StringUtils.trimToEmpty(a.getGroup()).equals(StringUtils.trimToEmpty(b.getGroup()))
                && StringUtils.trimToEmpty(a.getName()).equals(StringUtils.trimToEmpty(b.getName()))
                && StringUtils.trimToEmpty(a.getVersion()).equals(StringUtils.trimToEmpty(b.getVersion()))) {
            return true;
        }
        return false;
    }

    public static boolean doesIdentityMatch(final Component a, final Component b) {
        if (a == null || b == null) {
            return false;
        }
        if (isMatch(a.getPurl(), b.getPurl())) {
            return true;
        }
        if (isMatch(a.getPurlCoordinates(), b.getPurlCoordinates())) {
            return true;
        }
        if (isMatch(a.getSwidTagId(), b.getSwidTagId())) {
            return true;
        }
        if (isMatch(a.getCpe(), b.getCpe())) {
            return true;
        }
        if (StringUtils.trimToEmpty(a.getGroup()).equals(StringUtils.trimToEmpty(b.getGroup()))
                && StringUtils.trimToEmpty(a.getName()).equals(StringUtils.trimToEmpty(b.getName()))
                && StringUtils.trimToEmpty(a.getVersion()).equals(StringUtils.trimToEmpty(b.getVersion()))) {
            return true;
        }
        return false;
    }

    private static boolean isMatch(final PackageURL a, final PackageURL b) {
        if (a != null && b != null) {
            return a.canonicalize().equals(b.canonicalize());
        }
        return false;
    }

    private static boolean isMatch(final PackageURL a, final String b) {
        if (a != null && b != null) {
            try {
                return a.canonicalize().equals(new PackageURL(b).canonicalize());
            } catch (MalformedPackageURLException e) {
                return false;
            }
        }
        return false;
    }

    private static boolean isMatch(final String a, final String b) {
        if (StringUtils.trimToNull(a) != null && StringUtils.trimToNull(b) != null) {
            return StringUtils.trimToNull(a).equals(StringUtils.trimToNull(b));
        }
        return false;
    }
}
