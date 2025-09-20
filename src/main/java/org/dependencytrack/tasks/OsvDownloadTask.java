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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.osv.OsvAdvisoryParser;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.parser.osv.model.OsvAffectedPackage;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.CvssUtil;
import org.json.JSONObject;
import org.slf4j.MDC;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.zip.ZipInputStream;

import static org.dependencytrack.common.MdcKeys.MDC_VULN_ID;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
import static org.dependencytrack.model.Severity.getSeverityByLevel;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV2Score;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV3Score;

public class OsvDownloadTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(OsvDownloadTask.class);
    private Set<String> ecosystems;
    private String osvBaseUrl;
    private boolean aliasSyncEnabled;

    public OsvDownloadTask() {
        try (final QueryManager qm = new QueryManager()) {
            final var enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getGroupName(), VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getPropertyName());
            if (enabled == null) {
                return;
            }

            final var ecosystemConfig = enabled.getPropertyValue();
            if (ecosystemConfig != null) {
                ecosystems = Arrays.stream(ecosystemConfig.split(";")).map(String::trim).collect(Collectors.toSet());
            }

            this.osvBaseUrl = qm.getConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getGroupName(), VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getPropertyName()).getPropertyValue();
            if (this.osvBaseUrl != null && !this.osvBaseUrl.endsWith("/")) {
                this.osvBaseUrl += "/";
            }

            final var aliasSyncProperty = qm.getConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED.getGroupName(), VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED.getPropertyName());
            if (aliasSyncProperty != null) {
                this.aliasSyncEnabled = "true".equals(aliasSyncProperty.getPropertyValue());
            }
        }
    }

    @Override
    public void inform(Event e) {
        if (!(e instanceof OsvMirrorEvent)) {
            return;
        }

        if (this.ecosystems == null || this.ecosystems.isEmpty()) {
            LOGGER.info("Google OSV mirroring is disabled. No ecosystem selected.");
            return;
        }

        for (final var ecosystem : this.ecosystems) {
            LOGGER.info("Updating datasource with Google OSV advisories for ecosystem " + ecosystem);
            final var url = this.osvBaseUrl + URLEncoder.encode(ecosystem, StandardCharsets.UTF_8).replace("+", "%20") + "/all.zip";
            final var request = new HttpGet(url);
            try (final var ignoredMdcOsvEcosystem = MDC.putCloseable("osvEcosystem", ecosystem); final var response = HttpClientPool.getClient().execute(request)) {
                final var status = response.getStatusLine();
                if (status.getStatusCode() != HttpStatus.SC_OK) {
                    LOGGER.error("Download failed : " + status.getStatusCode() + ": " + status.getReasonPhrase());
                    continue;
                }

                final var tempFile = File.createTempFile("google-osv-download", ".zip");
                try {
                    try (final var out = new FileOutputStream(tempFile); final var in = response.getEntity().getContent()) {
                        out.write(in.readAllBytes());
                    }
                    try (final var in = new FileInputStream(tempFile); final var zipInput = new ZipInputStream(in)) {
                        unzipFolder(zipInput);
                    }
                } finally {
                    if (!tempFile.delete()) {
                        LOGGER.warn("Failed to delete temporary file: " + tempFile.getAbsolutePath());
                    }
                }
            } catch (Exception ex) {
                LOGGER.error("Exception while executing Http client request", ex);
            }
        }
    }

    private void unzipFolder(ZipInputStream zipIn) throws IOException {
        final var parser = new OsvAdvisoryParser();
        for (var zipEntry = zipIn.getNextEntry(); zipEntry != null; zipEntry = zipIn.getNextEntry()) {
            final var json = new JSONObject(IOUtils.toString(zipIn, StandardCharsets.UTF_8));
            final var advisoryId = json.optString("id");
            try (var ignored = MDC.putCloseable(MDC_VULN_ID, advisoryId)) {
                final var osvAdvisory = parser.parse(json);
                if (osvAdvisory != null) {
                    updateDatasource(osvAdvisory);
                }
            } catch (RuntimeException e) {
                LOGGER.error("Failed to process advisory", e);
            }
        }
    }

    public void updateDatasource(final OsvAdvisory advisory) {
        try (QueryManager qm = new QueryManager()) {
            LOGGER.debug("Synchronizing Google OSV advisory: " + advisory.getId());
            final var vulnerability = mapAdvisoryToVulnerability(advisory);
            final var vsListOld = qm.detach(qm.getVulnerableSoftwareByVulnId(vulnerability.getSource(), vulnerability.getVulnId()));
            final var existingVulnerability = qm.getVulnerabilityByVulnId(vulnerability.getSource(), vulnerability.getVulnId());
            final var vulnerabilitySource = extractSource(advisory.getId());
            final var vulnAuthoritativeSourceToggle = switch (vulnerabilitySource) {
                case NVD -> ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;
                case GITHUB -> ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;
                default -> VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
            };
            final var vulnAuthoritativeSourceEnabled = Boolean.parseBoolean(qm.getConfigProperty(vulnAuthoritativeSourceToggle.getGroupName(), vulnAuthoritativeSourceToggle.getPropertyName()).getPropertyValue());
            var synchronizedVulnerability = existingVulnerability;
            if (shouldUpdateExistingVulnerability(existingVulnerability, vulnerabilitySource, vulnAuthoritativeSourceEnabled)) {
                synchronizedVulnerability = qm.synchronizeVulnerability(vulnerability, false);
                if (synchronizedVulnerability == null) {
                    return; // Exit if nothing to update
                }
            }

            if (aliasSyncEnabled && advisory.getAliases() != null) {
                for (final var alias : advisory.getAliases()) {
                    final var vulnerabilityAlias = new VulnerabilityAlias();

                    // OSV will use IDs of other vulnerability databases for its
                    // primary advisory ID (e.g. GHSA-45hx-wfhj-473x). We need to ensure
                    // that we don't falsely report GHSA IDs as stemming from OSV.
                    switch (vulnerabilitySource) {
                        case NVD -> vulnerabilityAlias.setCveId(advisory.getId());
                        case GITHUB -> vulnerabilityAlias.setGhsaId(advisory.getId());
                        default -> vulnerabilityAlias.setOsvId(advisory.getId());
                    }

                    if (alias.startsWith("CVE") && Vulnerability.Source.NVD != vulnerabilitySource) {
                        vulnerabilityAlias.setCveId(alias);
                        qm.synchronizeVulnerabilityAlias(vulnerabilityAlias);
                    } else if (alias.startsWith("GHSA") && Vulnerability.Source.GITHUB != vulnerabilitySource) {
                        vulnerabilityAlias.setGhsaId(alias);
                        qm.synchronizeVulnerabilityAlias(vulnerabilityAlias);
                    }

                    //TODO - OSV supports GSD and DLA/DSA identifiers (possibly others). Determine how to handle.
                }
            }

            List<VulnerableSoftware> vsList = new ArrayList<>();
            for (final var osvAffectedPackage : advisory.getAffectedPackages()) {
                VulnerableSoftware vs = mapAffectedPackageToVulnerableSoftware(qm, osvAffectedPackage);
                if (vs != null) {
                    vsList.add(vs);
                }
            }
            qm.persist(vsList);
            qm.updateAffectedVersionAttributions(synchronizedVulnerability, vsList, Vulnerability.Source.OSV);
            vsList = qm.reconcileVulnerableSoftware(synchronizedVulnerability, vsListOld, vsList, Vulnerability.Source.OSV);
            synchronizedVulnerability.setVulnerableSoftware(vsList);
            qm.persist(synchronizedVulnerability);
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    private boolean shouldUpdateExistingVulnerability(Vulnerability existingVulnerability, Vulnerability.Source vulnerabilitySource, boolean vulnAuthoritativeSourceEnabled) {
        return Vulnerability.Source.OSV == vulnerabilitySource // Non GHSA nor NVD
                || existingVulnerability == null // Vuln is not replicated yet or declared by authoritative source with appropriate state
                || !vulnAuthoritativeSourceEnabled; // Vuln has been replicated but authoritative source is disabled
    }

    public Vulnerability mapAdvisoryToVulnerability(final OsvAdvisory advisory) {
        final var vuln = new Vulnerability();
        if (advisory.getId() != null) {
            vuln.setSource(extractSource(advisory.getId()));
        }
        vuln.setVulnId(String.valueOf(advisory.getId()));
        vuln.setTitle(advisory.getSummary());
        vuln.setDescription(advisory.getDetails());
        vuln.setPublished(Date.from(advisory.getPublished().toInstant()));
        vuln.setUpdated(Date.from(advisory.getModified().toInstant()));

        if (advisory.getCredits() != null) {
            vuln.setCredits(String.join(", ", advisory.getCredits()));
        }

        if (advisory.getReferences() != null && !advisory.getReferences().isEmpty()) {
            final var sb = new StringBuilder();
            for (final var ref : advisory.getReferences()) {
                sb.append("* [").append(ref).append("](").append(ref).append(")\n");
            }
            vuln.setReferences(sb.toString());
        }

        if (advisory.getCweIds() != null) {
            for (final var cweId : advisory.getCweIds()) {
                final var cwe = CweResolver.getInstance().lookup(cweId);
                if (cwe != null) {
                    vuln.addCwe(cwe);
                }
            }
        }
        vuln.setSeverity(calculateOSVSeverity(advisory));
        vuln.setCvssV2Vector(advisory.getCvssV2Vector());
        vuln.setCvssV3Vector(advisory.getCvssV3Vector());
        return vuln;
    }

    // calculate severity of vulnerability on priority-basis (database, ecosystem)
    public Severity calculateOSVSeverity(OsvAdvisory advisory) {
        // derive from database_specific cvss v3 vector if available
        if (advisory.getCvssV3Vector() != null) {
            final var cvss = CvssUtil.parse(advisory.getCvssV3Vector());
            if (cvss != null) {
                var score = cvss.getBakedScores();
                return normalizedCvssV3Score(score.getOverallScore());
            } else {
                LOGGER.warn("Unable to determine severity from CVSSv3 vector: " + advisory.getCvssV3Vector());
            }
        }

        // derive from database_specific cvss v2 vector if available
        if (advisory.getCvssV2Vector() != null) {
            final var cvss = CvssUtil.parse(advisory.getCvssV2Vector());
            if (cvss != null) {
                var score = cvss.getBakedScores();
                return normalizedCvssV2Score(score.getOverallScore());
            } else {
                LOGGER.warn("Unable to determine severity from CVSSv2 vector: " + advisory.getCvssV2Vector());
            }
        }

        // get database_specific severity string if available
        if (advisory.getSeverity() != null) {
            if (advisory.getSeverity().equalsIgnoreCase("CRITICAL")) {
                return Severity.CRITICAL;
            } else if (advisory.getSeverity().equalsIgnoreCase("HIGH")) {
                return Severity.HIGH;
            } else if (advisory.getSeverity().equalsIgnoreCase("MODERATE")) {
                return Severity.MEDIUM;
            } else if (advisory.getSeverity().equalsIgnoreCase("LOW")) {
                return Severity.LOW;
            }
        }

        // get largest ecosystem_specific severity from its affected packages
        if (advisory.getAffectedPackages().isEmpty()) {
            return Severity.UNASSIGNED;
        }

        final var severityLevels = new ArrayList<Integer>();
        for (final var vuln : advisory.getAffectedPackages()) {
            severityLevels.add(vuln.getSeverity().getLevel());
        }
        Collections.sort(severityLevels);
        return getSeverityByLevel(severityLevels.getLast());
    }

    public Vulnerability.Source extractSource(String vulnId) {
        final var sourceId = vulnId.split("-")[0];
        return switch (sourceId) {
            case "GHSA" -> Vulnerability.Source.GITHUB;
            case "CVE" -> Vulnerability.Source.NVD;
            default -> Vulnerability.Source.OSV;
        };
    }

    public VulnerableSoftware mapAffectedPackageToVulnerableSoftware(final QueryManager qm, final OsvAffectedPackage affectedPackage) {
        if (affectedPackage.getPurl() == null) {
            LOGGER.debug("No PURL provided for affected package " + affectedPackage.getPackageName() + " - skipping");
            return null;
        }

        final PackageURL purl;
        try {
            purl = new PackageURL(affectedPackage.getPurl());
        } catch (MalformedPackageURLException e) {
            LOGGER.debug("Invalid PURL provided for affected package  " + affectedPackage.getPackageName() + " - skipping", e);
            return null;
        }

        // Other sources do not populate the versionStartIncluding with 0.
        // Semantically, versionStartIncluding=null is equivalent to >=0.
        // Omit zero values here for consistency's sake.
        final var versionStartIncluding = Optional.ofNullable(affectedPackage.getLowerVersionRange()).filter(version -> !"0".equals(version)).orElse(null);
        final var versionEndExcluding = affectedPackage.getUpperVersionRangeExcluding();
        final var versionEndIncluding = affectedPackage.getUpperVersionRangeIncluding();

        var vs = qm.getVulnerableSoftwareByPurl(purl.getType(), purl.getNamespace(), purl.getName(), purl.getVersion(), versionEndExcluding, versionEndIncluding, null, versionStartIncluding);
        if (vs != null) {
            return vs;
        }

        vs = new VulnerableSoftware();
        vs.setPurlType(purl.getType());
        vs.setPurlNamespace(purl.getNamespace());
        vs.setPurlName(purl.getName());
        vs.setPurl(purl.canonicalize());
        vs.setVulnerable(true);
        vs.setVersion(affectedPackage.getVersion());
        vs.setVersionStartIncluding(versionStartIncluding);
        vs.setVersionEndExcluding(versionEndExcluding);
        vs.setVersionEndIncluding(versionEndIncluding);
        return vs;
    }

    public List<String> getEcosystems() {
        final var url = this.osvBaseUrl + "ecosystems.txt";
        final var request = new HttpGet(url);
        try (final var response = HttpClientPool.getClient().execute(request)) {
            final var status = response.getStatusLine();
            if (status.getStatusCode() != HttpStatus.SC_OK) {
                LOGGER.error("Ecosystem download failed : " + status.getStatusCode() + ": " + status.getReasonPhrase());
                return Collections.emptyList();
            }

            try (final var in = response.getEntity().getContent()) {
                return Arrays.stream(IOUtils.toString(in, StandardCharsets.UTF_8).split("\\R")).filter(line -> !line.isBlank()).map(String::trim).toList();
            }
        } catch (Exception ex) {
            LOGGER.error("Exception while executing Http request for ecosystems", ex);
        }

        return Collections.emptyList();
    }

    public Set<String> getEnabledEcosystems() {
        return Optional.ofNullable(this.ecosystems).orElseGet(Collections::emptySet);
    }
}