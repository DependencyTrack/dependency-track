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
package org.dependencytrack.vulnanalysis.internal;

import com.github.packageurl.PackageURL;
import org.jspecify.annotations.Nullable;
import us.springett.parsers.cpe.Cpe;

import java.util.HashSet;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
sealed interface Coordinate {

    record CpeCoordinate(String part, String vendor, String product) implements Coordinate {

        public CpeCoordinate {
            requireNonNull(part, "part must not be null");
            requireNonNull(vendor, "vendor must not be null");
            requireNonNull(product, "product must not be null");
        }

    }

    record PurlCoordinate(String type, @Nullable String namespace, String name) implements Coordinate {

        public PurlCoordinate {
            requireNonNull(type, "type must not be null");
            requireNonNull(name, "name must not be null");
        }

    }

    static Set<Coordinate> of(CandidateComponent component) {
        final var coordinates = new HashSet<Coordinate>(2);

        final Cpe cpe = component.parsedCpe();
        if (cpe != null) {
            coordinates.add(new Coordinate.CpeCoordinate(
                    cpe.getPart().getAbbreviation(),
                    cpe.getVendor().toLowerCase(),
                    cpe.getProduct().toLowerCase()));
        }

        final PackageURL purl = component.parsedPurl();
        if (purl != null) {
            coordinates.add(new Coordinate.PurlCoordinate(
                    purl.getType(),
                    purl.getNamespace(),
                    purl.getName()));
        }

        return coordinates;
    }

}
