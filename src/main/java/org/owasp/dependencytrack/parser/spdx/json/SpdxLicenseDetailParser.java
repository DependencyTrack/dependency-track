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
package org.owasp.dependencytrack.parser.spdx.json;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.owasp.dependencytrack.model.License;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

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
    public License parse(Path path) throws IOException {
        final byte[] jdon = Files.readAllBytes(path);
        final ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(jdon, License.class);
    }

    /**
     * Returns a List of License objects after parsing a directory of json
     * files.
     */
    public List<License> getLicenseDefinitions() throws IOException, URISyntaxException {
        final List<License> licenses = new ArrayList<>();
        final File dir = new File(getClass().getProtectionDomain().getCodeSource().getLocation().getPath()
                + "/license-list-data/json/details");
        final File[] files = dir.listFiles();
        if (files != null) {
            for (File nextFile : files) {
                final License license = parse(nextFile.toPath());
                licenses.add(license);
            }
        }
        return licenses;
    }
}
