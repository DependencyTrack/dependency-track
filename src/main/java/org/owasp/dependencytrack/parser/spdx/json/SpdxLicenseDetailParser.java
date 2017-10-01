/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
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
