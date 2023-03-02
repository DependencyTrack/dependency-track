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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.osv.OsvAdvisoryParser;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.parser.osv.model.OsvAffectedPackage;
import org.dependencytrack.persistence.QueryManager;
import org.json.JSONObject;
import us.springett.cvss.Cvss;
import us.springett.cvss.Score;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
import static org.dependencytrack.model.Severity.getSeverityByLevel;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV2Score;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV3Score;

public class OsvDownloadTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(OsvDownloadTask.class);
    private Set<String> ecosystems;
    private String osvBaseUrl;

    public OsvDownloadTask() {
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getGroupName(), VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getPropertyName());
            if (enabled != null) {
                final String ecosystemConfig = enabled.getPropertyValue();
                if (ecosystemConfig != null) {
                    ecosystems = Arrays.stream(ecosystemConfig.split(";")).map(String::trim).collect(Collectors.toSet());
                }
                this.osvBaseUrl = qm.getConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getGroupName(), VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getPropertyName()).getPropertyValue();
                if (this.osvBaseUrl != null && !this.osvBaseUrl.endsWith("/")) {
                    this.osvBaseUrl += "/";
                }
            }
        }
    }

    @Override
    public void inform(Event e) {

        if (e instanceof OsvMirrorEvent) {

            if (this.ecosystems != null && !this.ecosystems.isEmpty()) {
                for (String ecosystem : this.ecosystems) {
                    LOGGER.info("Updating datasource with Google OSV advisories for ecosystem " + ecosystem);
                    String url = this.osvBaseUrl + URLEncoder.encode(ecosystem, StandardCharsets.UTF_8).replace("+", "%20")
                            + "/all.zip";
                    HttpUriRequest request = new HttpGet(url);
                    try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                        final StatusLine status = response.getStatusLine();
                        if (status.getStatusCode() == HttpStatus.SC_OK) {
                            try (InputStream in = response.getEntity().getContent();
                                 ZipInputStream zipInput = new ZipInputStream(in)) {
                                unzipFolder(zipInput);
                            }
                        } else {
                            LOGGER.error("Download failed : " + status.getStatusCode() + ": " + status.getReasonPhrase());
                        }
                    } catch (Exception ex) {
                        LOGGER.error("Exception while executing Http client request", ex);
                    }
                }
            } else {
                LOGGER.info("Google OSV mirroring is disabled. No ecosystem selected.");
            }
        }
    }

    private void unzipFolder(ZipInputStream zipIn) throws IOException {

        BufferedReader reader = new BufferedReader(new InputStreamReader(zipIn));
        OsvAdvisoryParser parser = new OsvAdvisoryParser();
        ZipEntry zipEntry = zipIn.getNextEntry();
        while (zipEntry != null) {

            String line = null;
            StringBuilder out = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                out.append(line);
            }
            JSONObject json = new JSONObject(out.toString());
            final OsvAdvisory osvAdvisory = parser.parse(json);
            if (osvAdvisory != null) {
                updateDatasource(osvAdvisory);
            }
            zipEntry = zipIn.getNextEntry();
            reader = new BufferedReader(new InputStreamReader(zipIn));
        }
        reader.close();
    }

    public void updateDatasource(final OsvAdvisory advisory) {

        try (QueryManager qm = new QueryManager().withL2CacheDisabled()) {

            LOGGER.debug("Synchronizing Google OSV advisory: " + advisory.getId());
            final Vulnerability vulnerability = mapAdvisoryToVulnerability(qm, advisory);
            final List<VulnerableSoftware> vsListOld = qm.detach(qm.getVulnerableSoftwareByVulnId(vulnerability.getSource(), vulnerability.getVulnId()));
            final Vulnerability existingVulnerability = qm.getVulnerabilityByVulnId(vulnerability.getSource(), vulnerability.getVulnId());;
            final Vulnerability.Source vulnerabilitySource = extractSource(advisory.getId());
            final ConfigPropertyConstants vulnAuthoritativeSourceToggle = switch (vulnerabilitySource) {
                case NVD -> ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;
                case GITHUB -> ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;
                default -> VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
            };
            final boolean vulnAuthoritativeSourceEnabled = Boolean.valueOf(qm.getConfigProperty(vulnAuthoritativeSourceToggle.getGroupName(), vulnAuthoritativeSourceToggle.getPropertyName()).getPropertyValue());
            Vulnerability synchronizedVulnerability = existingVulnerability;
            if (shouldUpdateExistingVulnerability(existingVulnerability, vulnerabilitySource, vulnAuthoritativeSourceEnabled)) {
               synchronizedVulnerability  = qm.synchronizeVulnerability(vulnerability, false);
            }

            if (advisory.getAliases() != null) {
                for (int i = 0; i < advisory.getAliases().size(); i++) {
                    final String alias = advisory.getAliases().get(i);
                    final VulnerabilityAlias vulnerabilityAlias = new VulnerabilityAlias();

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
            for (OsvAffectedPackage osvAffectedPackage : advisory.getAffectedPackages()) {
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
        return (Vulnerability.Source.OSV == vulnerabilitySource) // Non GHSA nor NVD
                || (existingVulnerability == null) // Vuln is not replicated yet or declared by authoritative source with appropriate state
                || (existingVulnerability != null && !vulnAuthoritativeSourceEnabled); // Vuln has been replicated but authoritative source is disabled
    }

    public Vulnerability mapAdvisoryToVulnerability(final QueryManager qm, final OsvAdvisory advisory) {

        final Vulnerability vuln = new Vulnerability();
        if(advisory.getId() != null) {
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

        if (advisory.getReferences() != null && advisory.getReferences().size() > 0) {
            final StringBuilder sb = new StringBuilder();
            for (String ref : advisory.getReferences()) {
                sb.append("* [").append(ref).append("](").append(ref).append(")\n");
            }
            vuln.setReferences(sb.toString());
        }

        if (advisory.getCweIds() != null) {
            for (int i=0; i<advisory.getCweIds().size(); i++) {
                final Cwe cwe = CweResolver.getInstance().resolve(qm, advisory.getCweIds().get(i));
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
        if(advisory.getCvssV3Vector() != null) {
            Cvss cvss = Cvss.fromVector(advisory.getCvssV3Vector());
            Score score = cvss.calculateScore();
            return normalizedCvssV3Score(score.getBaseScore());
        }
        // derive from database_specific cvss v2 vector if available
        if (advisory.getCvssV2Vector() != null) {
            Cvss cvss = Cvss.fromVector(advisory.getCvssV2Vector());
            Score score = cvss.calculateScore();
            return normalizedCvssV2Score(score.getBaseScore());
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
        if (advisory.getAffectedPackages() != null) {
            List<Integer> severityLevels = new ArrayList<>();
            for (OsvAffectedPackage vuln : advisory.getAffectedPackages()) {
                severityLevels.add(vuln.getSeverity().getLevel());
            }
            Collections.sort(severityLevels);
            Collections.reverse(severityLevels);
            return getSeverityByLevel(severityLevels.get(0));
        }
        return Severity.UNASSIGNED;
    }

    public Vulnerability.Source extractSource(String vulnId) {
        final String sourceId = vulnId.split("-")[0];
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
        final String versionStartIncluding = Optional.ofNullable(affectedPackage.getLowerVersionRange())
                .filter(version -> !"0".equals(version))
                .orElse(null);
        final String versionEndExcluding = affectedPackage.getUpperVersionRangeExcluding();
        final String versionEndIncluding = affectedPackage.getUpperVersionRangeIncluding();

        VulnerableSoftware vs = qm.getVulnerableSoftwareByPurl(purl.getType(), purl.getNamespace(), purl.getName(),
                versionEndExcluding, versionEndIncluding, null, versionStartIncluding);
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
        ArrayList<String> ecosystems = new ArrayList<>();
        String url = this.osvBaseUrl + "ecosystems.txt";
        HttpUriRequest request = new HttpGet(url);
        try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            final StatusLine status = response.getStatusLine();
            if (status.getStatusCode() == HttpStatus.SC_OK) {
                try (InputStream in = response.getEntity().getContent();
                     Scanner scanner = new Scanner(in, StandardCharsets.UTF_8)) {
                    while (scanner.hasNextLine()) {
                        final String line = scanner.nextLine();
                        if(!line.isBlank()) {
                            ecosystems.add(line.trim());
                        }
                    }
                }
            } else {
                LOGGER.error("Ecosystem download failed : " + status.getStatusCode() + ": " + status.getReasonPhrase());
            }
        } catch (Exception ex) {
            LOGGER.error("Exception while executing Http request for ecosystems", ex);
        }
        return ecosystems;
    }

    public Set<String> getEnabledEcosystems() {
        return Optional.ofNullable(this.ecosystems)
                .orElseGet(Collections::emptySet);
    }

}