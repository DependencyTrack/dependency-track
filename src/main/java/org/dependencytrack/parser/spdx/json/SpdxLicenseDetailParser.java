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
package org.dependencytrack.parser.spdx.json;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.model.License;
import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

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
     * Reads in a json file and returns a License object.
     */
    public License parse(final Path path) throws IOException {
        final byte[] jdon = Files.readAllBytes(path);
        final ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(jdon, License.class);
    }

    /**
     * Returns a List of License objects after parsing a directory of json files.
     */
    public List<License> getLicenseDefinitions() throws IOException {
        final List<License> licenses = new ArrayList<>();
        final String[] dirs = {"/license-list-data/json/details", "/license-list-data/json/exceptions"};
        for (final String s: dirs) {
        	final File dir = new File(URLDecoder.decode(getClass().getProtectionDomain().getCodeSource().getLocation().getPath(), UTF_8.name()) + s);
            final File[] files = dir.listFiles();
            if (files != null) {
                for (final File nextFile : files) {
                    final License license = parse(nextFile.toPath());
                    licenses.add(license);
                }
            }
        }
        return licenses;
    }
}
