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

import com.github.packageurl.PackageURL;

import java.util.HashMap;
import java.util.Map;
import java.util.List;

/**
 * A class for producing Ecosystem objects, e.g. ubuntu.
 */
public class EcosystemFactory {
    private static final Map<String, Ecosystem> cache = new HashMap<>();

    public static Ecosystem getEcosystem(String name) {
        if(!cache.containsKey(name)) {
            if(name.equals(PackageURL.StandardTypes.DEBIAN)) {
                cache.put(PackageURL.StandardTypes.DEBIAN, new Ecosystem(PackageURL.StandardTypes.DEBIAN, List.of("~"), List.of("#"), List.of("\\d+", "[a-z]+", "\\+", "-", "\\.", ":")));
            }
            else  {
                cache.put(PackageURL.StandardTypes.GENERIC, new Ecosystem(PackageURL.StandardTypes.GENERIC, List.of("-"), List.of("#"), List.of("\\d+", "[a-z]+", "\\.")));
                name = PackageURL.StandardTypes.GENERIC;
            }
        }

        return cache.get(name);
    }
}

