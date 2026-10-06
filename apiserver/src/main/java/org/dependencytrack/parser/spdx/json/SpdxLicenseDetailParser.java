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
package org.dependencytrack.parser.spdx.json;

import org.dependencytrack.common.Mappers;
import org.dependencytrack.model.License;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Objects;

/**
 * This class parses json metadata file that describe each license. It does not
 * parse SPDX files themselves. License data is obtained from:
 *
 * https://github.com/spdx/license-list-data
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class SpdxLicenseDetailParser {

    /**
     * Returns a List of License objects after parsing the bundled license list.
     */
    public List<License> getLicenseDefinitions() throws IOException {
        try (final InputStream inputStream =
                Objects.requireNonNull(getClass().getResourceAsStream("/license-list-data/licenses.jsonl"))) {
            return Mappers.jsonMapper()
                    .readerFor(License.class)
                    .<License>readValues(inputStream)
                    .readAll();
        }
    }
}
