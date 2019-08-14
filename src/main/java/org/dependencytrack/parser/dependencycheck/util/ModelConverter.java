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
package org.dependencytrack.parser.dependencycheck.util;

import alpine.logging.Logger;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.persistence.QueryManager;
import java.math.BigDecimal;

/**
 * Utility class that converts various Dependency-Check and Dependency-Track
 * models to each others format.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class ModelConverter {

    private static final Logger LOGGER = Logger.getLogger(ModelConverter.class);

    /**
     * Private constructor.
     */
    private ModelConverter() { }

    /**
     * Converts a Vulnerability (parsed by Dependency-Track) to a native Dependency-Track Vulnerability.
     * @param parserVuln the parsed Dependency-Check vulnerability to convert
     * @return a native Vulnerability object
     */
    public static org.dependencytrack.model.Vulnerability convert(final QueryManager qm,
                                                                  final org.dependencytrack.parser.dependencycheck.model.Vulnerability parserVuln) {

        final org.dependencytrack.model.Vulnerability persistable = new org.dependencytrack.model.Vulnerability();
        if (parserVuln.getSource().equals("NSP")) {
            persistable.setSource("NPM");
        } else {
            persistable.setSource(parserVuln.getSource());
        }
        persistable.setVulnId(parserVuln.getName());

        persistable.setCwe(new CweResolver(qm).resolve(parserVuln.getCwe()));
        persistable.setDescription(parserVuln.getDescription());

        try {
            persistable.setCvssV2BaseScore(new BigDecimal(parserVuln.getCvssScore()));
        } catch (NumberFormatException e) {
            // throw it away
        }
        return persistable;
    }
}
