/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.persistence;

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

    /**
     * {@inheritDoc}
     */
    public PackageURL convertToAttribute(String str) {
        if (str == null) {
            return null;
        }

        final PackageURL url;
        try {
            url = new PackageURL(str.trim());
        } catch (MalformedPackageURLException e) {
            throw new IllegalStateException("Error converting the PackageURL", e);
        }
        return url;
    }

    /**
     * {@inheritDoc}
     */
    public String convertToDatastore(PackageURL url) {
        return url != null ? url.canonicalize() : null;
    }
}