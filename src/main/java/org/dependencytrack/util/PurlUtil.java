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

import static com.github.packageurl.PackageURLBuilder.aPackageURL;

public class PurlUtil {

    private PurlUtil() { }

    public static PackageURL purlCoordinatesOnly(final PackageURL original) throws MalformedPackageURLException {
        return aPackageURL()
                .withType(original.getType())
                .withNamespace(original.getNamespace())
                .withName(original.getName())
                .withVersion(original.getVersion())
                .build();
    }

    public static PackageURL silentPurlCoordinatesOnly(final PackageURL original) {
        if (original == null) {
            return null;
        }
        try {
            return aPackageURL()
                    .withType(original.getType())
                    .withNamespace(original.getNamespace())
                    .withName(original.getName())
                    .withVersion(original.getVersion())
                    .build();
        } catch (MalformedPackageURLException e) {
            return null;
        }
    }

}
