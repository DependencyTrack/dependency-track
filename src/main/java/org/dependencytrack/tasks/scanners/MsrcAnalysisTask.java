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
package org.dependencytrack.tasks.scanners;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.MsrcAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import org.json.JSONArray;
import org.json.JSONObject;

import java.time.YearMonth;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_MSRC_ENABLED;

/**
 * Subscriber task that performs analysis of Windows OS components using the
 * MSRC CVRF v2.0 REST API to identify unpatched CVEs.
 * <p>
 * The analyzer triggers on OPERATING_SYSTEM components with a Microsoft CPE,
 * extracts the OS build number and UBR from the version string, and compares
 * against FixedBuild values from MSRC monthly security update documents.
 */
public class MsrcAnalysisTask extends BaseComponentAnalyzerTask implements ScanTask, Subscriber {

    private static final Logger LOGGER = Logger.getLogger(MsrcAnalysisTask.class);
    private static final String MSRC_API_BASE = "https://api.msrc.microsoft.com/cvrf/v2.0";
    private static final Pattern CPE_MICROSOFT_OS = Pattern.compile(
            "cpe:2\\.3:o:microsoft:windows[^:]*:.*");
    // Matches version strings like 10.0.20348.2762 (major.minor.build.ubr)
    private static final Pattern VERSION_PATTERN = Pattern.compile(
            "(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)");
    // Maps MSRC build numbers to product name fragments for matching
    private static final int MONTHS_TO_QUERY = 3;

    private VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel;

    @Override
    public void inform(final Event e) {
        if (!(e instanceof final MsrcAnalysisEvent event)
                || !super.isEnabled(SCANNER_MSRC_ENABLED)) {
            return;
        }
        vulnerabilityAnalysisLevel = event.analysisLevel();
        LOGGER.info("Starting MSRC vulnerability analysis task");
        if (!event.components().isEmpty()) {
            analyze(event.components());
        }
        LOGGER.info("MSRC vulnerability analysis complete");
    }

    @Override
    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.MSRC_ANALYZER;
    }

    @Override
    public boolean isCapable(final Component component) {
        if (component.getCpe() == null) {
            return false;
        }
        return CPE_MICROSOFT_OS.matcher(component.getCpe()).matches();
    }

    @Override
    public void analyze(final List<Component> components) {
        final List<String> updateIds = getRecentUpdateIds();
        if (updateIds.isEmpty()) {
            LOGGER.warn("No MSRC update IDs resolved; Skipping analysis");
            return;
        }

        for (final Component component : components) {
            try {
                analyzeComponent(component, updateIds);
            } catch (Exception ex) {
                handleRequestException(LOGGER, ex);
            }
        }
    }

    private void analyzeComponent(final Component component, final List<String> updateIds) {
        final Matcher versionMatcher = VERSION_PATTERN.matcher(component.getVersion() != null ? component.getVersion() : "");
        if (!versionMatcher.find()) {
            LOGGER.debug("Component %s has no parseable Windows version; Skipping".formatted(component));
            return;
        }

        final int componentBuild = Integer.parseInt(versionMatcher.group(3));
        final int componentUbr = Integer.parseInt(versionMatcher.group(4));

        final String productIdPrefix = resolveProductIdPrefix(component.getCpe(), componentBuild);
        if (productIdPrefix == null) {
            LOGGER.debug("Unable to resolve MSRC product ID prefix for %s; Skipping".formatted(component.getCpe()));
            return;
        }

        boolean didCreateVulns = false;
        for (final String updateId : updateIds) {
            final JSONObject cvrfDoc = fetchCvrfDocument(updateId);
            if (cvrfDoc == null) {
                continue;
            }
            didCreateVulns |= processCvrfDocument(cvrfDoc, component, productIdPrefix, componentBuild, componentUbr);
        }

        if (didCreateVulns) {
            Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
        }
    }

    private boolean processCvrfDocument(final JSONObject cvrfDoc, final Component component,
                                        final String productIdPrefix, final int componentBuild,
                                        final int componentUbr) {
        final JSONArray vulnerabilities = cvrfDoc.optJSONArray("Vulnerability");
        if (vulnerabilities == null) {
            return false;
        }

        // Build product ID list from ProductTree matching our prefix
        final List<String> matchingProductIds = resolveMatchingProductIds(cvrfDoc, productIdPrefix);
        if (matchingProductIds.isEmpty()) {
            return false;
        }

        boolean didCreate = false;
        for (int i = 0; i < vulnerabilities.length(); i++) {
            final JSONObject vuln = vulnerabilities.getJSONObject(i);
            final String cveId = extractCveId(vuln);
            if (cveId == null) {
                continue;
            }

            if (isComponentAffected(vuln, matchingProductIds, componentBuild, componentUbr)) {
                didCreate |= createVulnerability(component, vuln, cveId);
            }
        }
        return didCreate;
    }

    private boolean isComponentAffected(final JSONObject vuln, final List<String> matchingProductIds,
                                        final int componentBuild, final int componentUbr) {
        final JSONArray remediations = vuln.optJSONArray("Remediations");
        if (remediations == null) {
            return false;
        }

        for (int r = 0; r < remediations.length(); r++) {
            final JSONObject remediation = remediations.getJSONObject(r);
            final String fixedBuild = remediation.optString("FixedBuild", null);
            if (fixedBuild == null || fixedBuild.isBlank()) {
                continue;
            }

            // Check if this remediation applies to any of our matching product IDs
            final JSONArray productIds = remediation.optJSONArray("ProductID");
            if (productIds == null) {
                continue;
            }

            boolean appliesToProduct = false;
            for (int p = 0; p < productIds.length(); p++) {
                if (matchingProductIds.contains(productIds.getString(p))) {
                    appliesToProduct = true;
                    break;
                }
            }
            if (!appliesToProduct) {
                continue;
            }

            // Compare UBR: if component UBR < fixed UBR for the same build, it's vulnerable
            final Matcher fixedMatcher = VERSION_PATTERN.matcher(fixedBuild);
            if (fixedMatcher.find()) {
                final int fixedBuildNum = Integer.parseInt(fixedMatcher.group(3));
                final int fixedUbr = Integer.parseInt(fixedMatcher.group(4));
                if (fixedBuildNum == componentBuild && componentUbr < fixedUbr) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean createVulnerability(final Component component, final JSONObject vuln, final String cveId) {
        try (final var qm = new QueryManager()) {
            final var persistentComponent = qm.getObjectByUuid(Component.class, component.getUuid());
            if (persistentComponent == null) {
                LOGGER.warn("Component %s no longer exists; Skipping".formatted(component.getUuid()));
                return false;
            }

            Vulnerability vulnerability = qm.getVulnerabilityByVulnId(Vulnerability.Source.MSRC, cveId);
            if (vulnerability == null) {
                final var newVuln = new Vulnerability();
                newVuln.setVulnId(cveId);
                newVuln.setSource(Vulnerability.Source.MSRC);
                newVuln.setSeverity(extractSeverity(vuln));
                newVuln.setDescription(extractDescription(vuln));
                newVuln.setReferences("* [" + cveId + "](https://msrc.microsoft.com/update-guide/vulnerability/" + cveId + ")");
                vulnerability = qm.createVulnerability(newVuln, false);
            }

            NotificationUtil.analyzeNotificationCriteria(qm, vulnerability, persistentComponent, vulnerabilityAnalysisLevel);
            qm.addVulnerability(vulnerability, persistentComponent, getAnalyzerIdentity());
            LOGGER.debug("MSRC vulnerability added: %s to component %s".formatted(cveId, persistentComponent.getName()));
            return true;
        }
    }

    private String extractCveId(final JSONObject vuln) {
        final JSONArray cveArray = vuln.optJSONArray("CVE");
        if (cveArray != null && !cveArray.isEmpty()) {
            return cveArray.getString(0);
        }
        // Some CVRF docs use a single CVE string field
        final String cve = vuln.optString("CVE", null);
        if (cve != null && cve.startsWith("CVE-")) {
            return cve;
        }
        return null;
    }

    private Severity extractSeverity(final JSONObject vuln) {
        final JSONArray threats = vuln.optJSONArray("Threats");
        if (threats != null) {
            for (int t = 0; t < threats.length(); t++) {
                final JSONObject threat = threats.getJSONObject(t);
                // Type 3 = "Impact" which contains severity
                if (threat.optInt("Type", -1) == 3) {
                    final JSONObject desc = threat.optJSONObject("Description");
                    if (desc != null) {
                        final String value = desc.optString("Value", "").toUpperCase();
                        return switch (value) {
                            case "CRITICAL" -> Severity.CRITICAL;
                            case "IMPORTANT" -> Severity.HIGH;
                            case "MODERATE" -> Severity.MEDIUM;
                            case "LOW" -> Severity.LOW;
                            default -> Severity.UNASSIGNED;
                        };
                    }
                }
            }
        }
        return Severity.UNASSIGNED;
    }

    private String extractDescription(final JSONObject vuln) {
        final JSONArray notes = vuln.optJSONArray("Notes");
        if (notes != null) {
            for (int n = 0; n < notes.length(); n++) {
                final JSONObject note = notes.getJSONObject(n);
                // Type 1 = "Description"
                if (note.optInt("Type", -1) == 1) {
                    return note.optString("Value", null);
                }
            }
        }
        return vuln.optString("Title", null);
    }

    private List<String> resolveMatchingProductIds(final JSONObject cvrfDoc, final String productIdPrefix) {
        final var result = new ArrayList<String>();
        final JSONObject productTree = cvrfDoc.optJSONObject("ProductTree");
        if (productTree == null) {
            return result;
        }
        final JSONArray fullProductNames = productTree.optJSONArray("FullProductName");
        if (fullProductNames == null) {
            return result;
        }
        for (int i = 0; i < fullProductNames.length(); i++) {
            final JSONObject product = fullProductNames.getJSONObject(i);
            final String productId = product.optString("ProductID", "");
            final String value = product.optString("Value", "").toLowerCase();
            if (value.contains(productIdPrefix)) {
                result.add(productId);
            }
        }
        return result;
    }

    /**
     * Maps a CPE and build number to a product name fragment used to match
     * MSRC ProductTree entries.
     */
    private String resolveProductIdPrefix(final String cpe, final int buildNumber) {
        final String cpeLower = cpe.toLowerCase();
        if (cpeLower.contains("windows_server_2022")) {
            return "windows server 2022";
        } else if (cpeLower.contains("windows_server_2019")) {
            return "windows server 2019";
        } else if (cpeLower.contains("windows_server_2016")) {
            return "windows server 2016";
        } else if (cpeLower.contains("windows_11")) {
            return "windows 11";
        } else if (cpeLower.contains("windows_10")) {
            return "windows 10";
        } else if (cpeLower.contains("windows_server_2025")) {
            return "windows server 2025";
        }
        return null;
    }

    private List<String> getRecentUpdateIds() {
        final var updateIds = new ArrayList<String>();
        final YearMonth now = YearMonth.now();
        final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MMM");
        for (int i = 0; i < MONTHS_TO_QUERY; i++) {
            updateIds.add(now.minusMonths(i).format(formatter));
        }
        return updateIds;
    }

    private JSONObject fetchCvrfDocument(final String updateId) {
        final String url = "%s/Updates('%s')".formatted(MSRC_API_BASE, updateId);
        final var request = new HttpGet(url);
        request.setHeader(HttpHeaders.ACCEPT, "application/json");
        request.setHeader(HttpHeaders.USER_AGENT, ManagedHttpClientFactory.getUserAgent());

        try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            final int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode >= HttpStatus.SC_OK && statusCode < HttpStatus.SC_MULTIPLE_CHOICES) {
                final String body = EntityUtils.toString(response.getEntity());
                return new JSONObject(body);
            } else {
                handleUnexpectedHttpResponse(LOGGER, url, statusCode, response.getStatusLine().getReasonPhrase());
            }
        } catch (Exception ex) {
            handleRequestException(LOGGER, ex);
        }
        return null;
    }
}
