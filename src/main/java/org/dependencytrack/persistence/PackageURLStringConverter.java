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
package org.dependencytrack.persistence;

import alpine.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import javax.jdo.AttributeConverter;

/**
 * This class allows the persistence of PackageURLs in the database by converting
 * the class to a format that can be stored in the database. In this case, the
 * canonicalized PackageURL syntax is stored as a String and converted to PackageURL
 * when being retrieved.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class PackageURLStringConverter implements AttributeConverter<PackageURL, String> {

    private static final Logger LOGGER = Logger.getLogger(PackageURLStringConverter.class);

    /**
     * {@inheritDoc}
     */
    public PackageURL convertToAttribute(final String str) {
        if (str == null) {
            return null;
        }

        try {
            return new PackageURL(str.trim());
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("A persisted object with a PackageURL string in the datastore failed validation and is not valid. Returning null for: " + str);
        }
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String convertToDatastore(final PackageURL url) {
        return url != null ? url.canonicalize() : null;
    }
}