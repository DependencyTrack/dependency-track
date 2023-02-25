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
package org.dependencytrack.parser.epss;

import alpine.common.logging.Logger;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * Parser and processor of EPSS data.
 *
 * @author Steve Springett
 * @since 4.5.0
 */
public final class EpssParser {

    private static final Logger LOGGER = Logger.getLogger(EpssParser.class);

    public void parse(final File file) {
        if (!file.getName().endsWith(".csv")) {
            return;
        }
        LOGGER.info("Parsing " + file.getName());
        try (final Scanner scanner = new Scanner(file)) {
            while (scanner.hasNextLine()) {
                final List<String> values = new ArrayList<>();
                try (final Scanner rowScanner = new Scanner(scanner.nextLine())) {
                    rowScanner.useDelimiter(",");
                    while (rowScanner.hasNext()) {
                        values.add(rowScanner.next());
                    }
                }
                if (values.get(0).startsWith("CVE-")) {
                    final String cveId = values.get(0);
                    final BigDecimal epssScore = new BigDecimal(values.get(1));
                    final BigDecimal percentile = new BigDecimal(values.get(2));
                    try (final QueryManager qm = new QueryManager().withL2CacheDisabled()) {
                        final Vulnerability vuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, cveId);
                        if (vuln != null) {
                            vuln.setEpssScore(epssScore);
                            vuln.setEpssPercentile(percentile);
                            qm.persist(vuln);
                        }
                    }
                }
            }
        } catch (FileNotFoundException e) {
            LOGGER.error("An error occurred while parsing EPSS data", e);
        }
    }
}
