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
package org.dependencytrack.vulndatasource.api;

import org.cyclonedx.proto.v1_7.Bom;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;

import java.util.Iterator;

/**
 * A source of vulnerability intelligence data.
 * <p>
 * Data is exchanged in the CycloneDX Bill of Vulnerabilities (BOV) format.
 *
 * <h3>Expected BOV content</h3>
 * Each BOV must contain <em>at most</em> one vulnerability.
 * <p>
 * CPE and PURL coordinates of affected components may be communicated by linking
 * to component items within the same BOV, using BOM refs.
 * <p>
 * If CPEs and PURLs contain versions (e.g. {@code pkg:maven/foo/bar@1.2.3}),
 * those versions are overwritten by the {@code affects} version that links to them.
 *
 * <h3>Custom properties</h3>
 * Sources may populate the {@code dependency-track:vuln:title} property
 * to communicate a short, human-friendly title.
 *
 * <h3>Valid example BOV</h3>
 * <pre>{@code
 * {
 *   "components": [
 *     {
 *       "bom-ref": "00000000-0000-0000-0000-000000000000",
 *       "name": "acme-lib",
 *       "purl": "pkg:maven/com.acme/acme-lib"
 *     }
 *   ],
 *   "vulnerabilities": [
 *     {
 *       "id": "CVE-123",
 *       "source": {
 *         "name": "NVD"
 *       },
 *       "affects": [
 *         {
 *           "ref": "00000000-0000-0000-0000-000000000000",
 *           "versions": [
 *             {
 *               "version": "1.2.3"
 *             },
 *             {
 *               "range": "vers:maven/>=2.0.0|<3.2.1"
 *             }
 *           ]
 *         }
 *       ]
 *     }
 *   ]
 * }
 * }</pre>
 *
 * <h3>Expected {@link Iterator} behavior</h3>
 * It is expected that sources make an effort to keep as little data as possible
 * in memory, and lazily retrieve new data as {@link Iterator#hasNext()} is invoked.
 * <p>
 * Sources may deviate from this behavior to improve performance by buffering,
 * or to avoid rate limiting of external APIs.
 *
 * @see <a href="https://cyclonedx.org/capabilities/bov/">CycloneDX BOV</a>
 * @since 5.0.0
 */
@ExtensionPointSpec(name = "vuln-data-source", required = false)
public interface VulnDataSource extends ExtensionPoint, Iterator<Bom> {

    /**
     * Marks a given BOV as processed, enabling the data source to advance its watermark.
     * <p>
     * This is only relevant for data sources that support incremental retrieval.
     *
     * @param bov The BOV to be marked as processed.
     */
    default void markProcessed(Bom bov) {
    }

}