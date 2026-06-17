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
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.nio.file.FileSystems;
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
    private static License parse(final Path path) {
        try {
            final byte[] jdon = Files.readAllBytes(path);
            return Mappers.jsonMapper().readValue(jdon, License.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Returns a List of License objects after parsing a directory of json files.
     */
    public List<License> getLicenseDefinitions() throws IOException {
        final List<License> licenses = new ArrayList<>();
        final String[] dirs = {"/license-list-data/json/details", "/license-list-data/json/exceptions"};

        final Path codeSource;
        try {
            codeSource = Path.of(getClass().getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (URISyntaxException e) {
            throw new IOException(e);
        }

        if (Files.isDirectory(codeSource)) {
            for (final String dir : dirs) {
                licenses.addAll(parseLicenses(codeSource.resolve(dir.substring(1))));
            }
        } else {
            try (final var fs = FileSystems.newFileSystem(codeSource)) {
                for (final String dir : dirs) {
                    licenses.addAll(parseLicenses(fs.getPath(dir)));
                }
            }
        }

        return licenses;
    }

    private static List<License> parseLicenses(Path dir) throws IOException {
        if (!Files.isDirectory(dir)) {
            return List.of();
        }

        try (final var files = Files.list(dir)) {
            return files
                    .map(SpdxLicenseDetailParser::parse)
                    .toList();
        }
    }

}
