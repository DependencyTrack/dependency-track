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
package org.dependencytrack.vulnanalysis.api;

import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;

/**
 * An {@link ExtensionPoint} for vulnerability analyzers.
 * <p>
 * Implementations receive a CycloneDX BOM representing a project's components,
 * and produce a Vulnerability Disclosure Report (VDR) describing discovered vulnerabilities.
 *
 * @since 5.0.0
 */
@ExtensionPointSpec(name = "vuln-analyzer")
public interface VulnAnalyzer extends ExtensionPoint {

    /**
     * Analyzes the given BOM for vulnerabilities.
     *
     * <h4>Input</h4>
     * <p>
     * The input is a CycloneDX BOM representing a project's components.
     * Components MAY have the fields indicated by the analyzer's
     * {@link VulnAnalyzerFactory#analyzerRequirements()}, but this is not guaranteed.
     * Components can have more or fewer fields. It is the responsibility of the analyzer
     * to determine which components it can work with and which it should ignore.
     * <p>
     * Components may include a {@code dependencytrack:internal:is-internal-component} property.
     * When present, the component is internal and its data MUST NOT be sent to external services.
     * The mere presence of the property is suffices, the value is irrelevant. Example:
     * <pre>{@code
     * {
     *   "components": [
     *     {
     *       "bomRef": "ab84cf35-82a1-4341-a70f-0e8c9138e3c4",
     *       "type": "CLASSIFICATION_LIBRARY",
     *       "name": "acme-lib",
     *       "version": "1.0.0",
     *       "purl": "pkg:maven/com.acme/acme-lib@1.0.0",
     *       "properties": [
     *         {
     *           "name": "dependencytrack:internal:is-internal-component"
     *         }
     *       ]
     *     },
     *     {
     *       "bomRef": "cd72ef49-93b2-4452-b81e-1a9249fce4b5",
     *       "type": "CLASSIFICATION_LIBRARY",
     *       "name": "jackson-databind",
     *       "version": "2.18.0",
     *       "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.18.0",
     *       "cpe": "cpe:2.3:a:fasterxml:jackson-databind:2.18.0:*:*:*:*:*:*:*"
     *     }
     *   ]
     * }
     * }</pre>
     *
     * <h4>Output</h4>
     * <p>
     * The output is a CycloneDX VDR. It must contain {@code vulnerabilities} with
     * {@link VulnerabilityAffects} entries referencing affected components via their {@code bomRef}.
     * BOM refs should be treated as opaque strings, and analyzers should not make assumptions
     * about their format. Example:
     * <pre>{@code
     * {
     *   "vulnerabilities": [
     *     {
     *       "id": "CVE-2024-1234",
     *       "source": {
     *         "name": "NVD",
     *         "url": "https://nvd.nist.gov/"
     *       },
     *       "affects": [
     *         {
     *           "ref": "cd72ef49-93b2-4452-b81e-1a9249fce4b5"
     *         }
     *       ]
     *     }
     *   ]
     * }
     * }</pre>
     * <p>
     * Vulnerabilities MAY include a {@code dependency-track:vuln:reference-url} property,
     * containing a URL that links to the analyzer-specific advisory or issue page for the
     * vulnerability. Example:
     * <pre>{@code
     * {
     *   "vulnerabilities": [
     *     {
     *       "id": "CVE-2024-1234",
     *       "source": {
     *         "name": "NVD"
     *       },
     *       "properties": [
     *         {
     *           "name": "dependency-track:vuln:reference-url",
     *           "value": "https://security.snyk.io/vuln/SNYK-JAVA-EXAMPLE-1234"
     *         }
     *       ],
     *       "affects": [
     *         {
     *           "ref": "cd72ef49-93b2-4452-b81e-1a9249fce4b5"
     *         }
     *       ]
     *     }
     *   ]
     * }
     * }</pre>
     *
     * @param bom the CycloneDX BOM to analyze.
     * @return A CycloneDX VDR containing discovered vulnerabilities.
     * @throws InterruptedException           When interrupted.
     * @throws RetryableVulnAnalysisException When analysis failed with a retryable cause.
     */
    Bom analyze(Bom bom) throws InterruptedException;

}
