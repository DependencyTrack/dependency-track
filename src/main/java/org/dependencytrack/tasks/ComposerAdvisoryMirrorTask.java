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

import java.io.IOException;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;

import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.ComposerAdvisoryMirrorEvent;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.composer.ComposerSecurityAdvisoryParser;
import org.dependencytrack.parser.composer.model.ComposerVulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.json.JSONObject;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;

public class ComposerAdvisoryMirrorTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(ComposerAdvisoryMirrorTask.class);
    //TODO replace with url from Repository
    private static final String COMPOSER_SECURITY_API = "https://packagist.org/api/security-advisories/?updatedSince=100";
    // private static final String COMPOSER_SECURITY_API = "https://packages.drupal.org/8/security-advisories?updatedSince=100";

    private final boolean isEnabled;
    private final boolean isAliasSyncEnabled;
    private boolean mirroredWithoutErrors = true;

    public ComposerAdvisoryMirrorTask() {
        try (final QueryManager qm = new QueryManager()) {

            //TODO get from Repository property
            // final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_COMPOSER_ADVISORIES_ENABLED.getGroupName(), VULNERABILITY_SOURCE_COMPOSER_ADVISORIES_ENABLED.getPropertyName());
            // this.isEnabled = enabled != null && Boolean.parseBoolean(enabled.getPropertyValue());
            // final ConfigProperty aliasSyncEnabled = qm.getConfigProperty(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED.getGroupName(), VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED.getPropertyName());
            // isAliasSyncEnabled = aliasSyncEnabled != null && Boolean.parseBoolean(aliasSyncEnabled.getPropertyValue());
            isEnabled = true;
            isAliasSyncEnabled = true;

        }
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof ComposerAdvisoryMirrorEvent && this.isEnabled) {
            final long start = System.currentTimeMillis();
            LOGGER.info("Starting Composer Advisory mirroring task");
            try {
                retrieveAdvisories();
            } catch (IOException ex) {
                handleRequestException(LOGGER, ex);
            }
            final long end = System.currentTimeMillis();
            LOGGER.info("Composer Advisory mirroring complete");
            LOGGER.info("Time spent (total): " + (end - start) + "ms");

            if (mirroredWithoutErrors) {
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.DATASOURCE_MIRRORING)
                        .title(NotificationConstants.Title.COMPOSER_ADVISORY_MIRROR)
                        .content("Mirroring of Composer Advisories completed successfully")
                        .level(NotificationLevel.INFORMATIONAL)
                );
            } else {
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.DATASOURCE_MIRRORING)
                        .title(NotificationConstants.Title.COMPOSER_ADVISORY_MIRROR)
                        .content("An error occurred mirroring the contents of Composer Advisories. Check log for details.")
                        .level(NotificationLevel.ERROR)
                );
            }
        }
    }

    private void retrieveAdvisories() throws IOException {
        HttpPost request = new HttpPost(COMPOSER_SECURITY_API);
        request.addHeader("content-type", "application/json");
        request.addHeader("accept", "application/json");
        //TODO use updatedSince to do incremental mirroring
        try (CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                LOGGER.error("An error was encountered retrieving advisories with HTTP Status : " + response.getStatusLine().getStatusCode() + " " + response.getStatusLine().getReasonPhrase());
                LOGGER.error(Arrays.toString(response.getAllHeaders()));
                mirroredWithoutErrors = false;
            } else {
                var parser = new ComposerSecurityAdvisoryParser();
                String responseString = EntityUtils.toString(response.getEntity());
                // LOGGER.debug("response from composer repository: \n" + responseString);
                var jsonObject = new JSONObject(responseString);
                final List<ComposerVulnerability> advisories = parser.parse(jsonObject);
                updateDatasource(advisories);
            }
        } catch (Exception ex) {
            LOGGER.error("Exception while executing Http client request", ex);
        }
    }

    /**
     * Synchronizes the advisories that were downloaded with the internal Dependency-Track database.
     *
     * @param advisories the results to synchronize
     */
    void updateDatasource(final List<ComposerVulnerability> advisories) {
        LOGGER.debug("Updating datasource with Composer advisories");
        try (QueryManager qm = new QueryManager()) {
            for (final ComposerVulnerability advisory : advisories) {
                LOGGER.debug("Synchronizing Composer advisory: " + advisory.getAdvisoryId());

                final Vulnerability mappedVulnerability = mapComposerVulnerabilityToVulnerability(qm, advisory);
                final List<VulnerableSoftware> vsListOld = qm.detach(qm.getVulnerableSoftwareByVulnId(mappedVulnerability.getSource(), mappedVulnerability.getVulnId()));

                final Vulnerability existingVulnerability = qm.getVulnerabilityByVulnId(mappedVulnerability.getSource(), mappedVulnerability.getVulnId());

                final Vulnerability.Source vulnerabilitySource = Vulnerability.Source.resolve(mappedVulnerability.getSource());
                final ConfigPropertyConstants vulnAuthoritativeSourceToggle = switch (vulnerabilitySource) {
                    case Vulnerability.Source.NVD -> ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;
                    case Vulnerability.Source.GITHUB -> ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;
                    default -> ConfigPropertyConstants.VULNERABILITY_SOURCE_COMPOSER_ENABLED;
                };
                final boolean vulnAuthoritativeSourceEnabled = Boolean.valueOf(qm.getConfigProperty(vulnAuthoritativeSourceToggle.getGroupName(), vulnAuthoritativeSourceToggle.getPropertyName()).getPropertyValue());
                Vulnerability synchronizedVulnerability = existingVulnerability;
                if (shouldUpdateExistingVulnerability(existingVulnerability, vulnerabilitySource, vulnAuthoritativeSourceEnabled)) {
                    synchronizedVulnerability  = qm.synchronizeVulnerability(mappedVulnerability, false);
                    if (synchronizedVulnerability == null) continue; //No changes in vulnerability
                }

                List<VulnerableSoftware> vsList = mapVulnerabilityToVulnerableSoftware(qm, advisory);
                if (isAliasSyncEnabled) {
                    for (VulnerabilityAlias alias: mappedVulnerability.getAliases()) {
                        qm.synchronizeVulnerabilityAlias(alias);
                    }
                }
                LOGGER.debug("Updating vulnerable software for advisory: " + advisory.getAdvisoryId());
                qm.persist(vsList);
                final Vulnerability finalSynchronizedVulnerability = synchronizedVulnerability;
                vsList.forEach(vs -> qm.updateAffectedVersionAttribution(finalSynchronizedVulnerability, vs, Vulnerability.Source.COMPOSER));
                vsList = qm.reconcileVulnerableSoftware(synchronizedVulnerability, vsListOld, vsList, Vulnerability.Source.COMPOSER);
                synchronizedVulnerability.setVulnerableSoftware(vsList);
                qm.persist(synchronizedVulnerability);
            }
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    private boolean shouldUpdateExistingVulnerability(Vulnerability existingVulnerability, Vulnerability.Source vulnerabilitySource, boolean vulnAuthoritativeSourceEnabled) {
        return (Vulnerability.Source.COMPOSER == vulnerabilitySource) // Non GHSA nor NVD nor DRUPAL
                || (existingVulnerability == null) // Vuln is not replicated yet or declared by authoritative source with appropriate state
                || (existingVulnerability != null && !vulnAuthoritativeSourceEnabled); // Vuln has been replicated but authoritative source is disabled
    }

    /**
     * Helper method that maps an GitHub SecurityAdvisory object to a Dependency-Track vulnerability object.
     *
     * @param composerVulnerability the GitHub SecurityAdvisory to map
     * @return a Dependency-Track Vulnerability object
     */
    private Vulnerability mapComposerVulnerabilityToVulnerability(final QueryManager qm, final ComposerVulnerability composerVulnerability) {
        final Vulnerability vuln = new Vulnerability();

        /**
         * First determine what the primay ID of the vulnerability is.
         * Authoritative sources take precedence over non-authoritative sources.
         */
        VulnerabilityAlias alias = new VulnerabilityAlias();
        alias.setComposerId(composerVulnerability.getAdvisoryId());
        if (composerVulnerability.getAdvisoryId().startsWith("SA-CORE") || composerVulnerability.getAdvisoryId().startsWith("SA-CONTRIB")) {
            vuln.setSource(Vulnerability.Source.DRUPAL);
            alias.setCveId(composerVulnerability.getCve());
            alias.setDrupalId(composerVulnerability.getAdvisoryId());
            // use sources as alias
        } else if (composerVulnerability.getCve() != null && composerVulnerability.getCve().startsWith("CVE")) {
            vuln.setVulnId(composerVulnerability.getCve());
            vuln.setSource(Vulnerability.Source.NVD);
            alias.setCveId(composerVulnerability.getCve());
            // use PKSA as alias
            // use sources as alias
        } else if (composerVulnerability.getRemoteId() != null && composerVulnerability.getRemoteId().startsWith("GHSA")) {
            vuln.setVulnId(composerVulnerability.getRemoteId());
            vuln.setSource(Vulnerability.Source.GITHUB);
            alias.setGhsaId(composerVulnerability.getRemoteId());
            // use sources as alias
        } else if (composerVulnerability.getSources() != null && composerVulnerability.getSources().containsKey("github")) {
            vuln.setVulnId(composerVulnerability.getSources().get("github"));
            vuln.setSource(Vulnerability.Source.GITHUB);
            alias.setGhsaId(composerVulnerability.getRemoteId());
            // use sources as alias
        } else {
            vuln.setVulnId(composerVulnerability.getAdvisoryId());
            //Example Id PKSA-jvj8-gbfh-v875, where PKSA stands for Packagist Security Advisory (I think)
            //Should this be another SOURCE? DT uses sources for sources and for analyzers, which are slighly different
            //But adding an extra source feels to much. Or should we rename the new COMPOSER source to PACKAGIST?
            vuln.setSource(Vulnerability.Source.COMPOSER);
        }

        //Make sure RemoteId is always used as alias if present
        if (composerVulnerability.getRemoteId() != null) {
            String remoteId = composerVulnerability.getRemoteId();
            if (remoteId.startsWith("GHSA") && alias.getGhsaId() == null) {
                alias.setGhsaId(remoteId);
            }
            if (remoteId.startsWith("CVE") && alias.getCveId() == null) {
                alias.setCveId(remoteId);
            }
        }
        vuln.setAliases(Arrays.asList(alias));

        String description = composerVulnerability.getTitle() + " in " + composerVulnerability.getPackageName() + " " + composerVulnerability.getAffectedVersions();
        List<String> references = new ArrayList<>();
        references.add(composerVulnerability.getLink());
        for (Entry<String, String> source: composerVulnerability.getSources().entrySet()) {
            if (source.getKey().equalsIgnoreCase("github")) {
                references.add("https://github.com/advisories/" + source.getValue());
                if (alias.getGhsaId() == null) alias.setGhsaId(source.getValue());
            } else if (source.getKey().equalsIgnoreCase("friendsofphp/security-advisories")) {
                references.add("https://github.com/FriendsOfPHP/security-advisories/blob/master/" + source.getValue());
                description += "\nUnmapped alias: " + source.getKey() + " : " + source.getValue() + "\n";
            } else {
                description += "\nUnmapped alias: " + source.getKey() + " : " + source.getValue() + "\n";
            }
        }
        references.add(composerVulnerability.getComposerRepository());

        if (!references.isEmpty()) {
            final StringBuilder sb = new StringBuilder();
            for (String ref : references) {
                // Convert reference to Markdown format;
                sb.append("* [").append(ref).append("](").append(ref).append(")\n");
            }
            vuln.setReferences(sb.toString());
        }

        vuln.setDescription(description);
        vuln.setTitle(composerVulnerability.getTitle());
        if (composerVulnerability.getReportedAt() != null) {
            vuln.setPublished(Date.from(composerVulnerability.getReportedAt().toInstant(ZoneOffset.UTC)));
            // Should we leave Updated null?
            vuln.setUpdated(Date.from(composerVulnerability.getReportedAt().toInstant(ZoneOffset.UTC)));
        }

        if (composerVulnerability.getAffectedVersions() != null && composerVulnerability.getAffectedVersions().length() > 255) {
            // https://github.com/DependencyTrack/dependency-track/issues/4512
            LOGGER.warn("Affected versions for " + composerVulnerability.getAdvisoryId() + " is too long. Truncating to 255 characters.");
            vuln.setVulnerableVersions(composerVulnerability.getAffectedVersions().substring(0, 254));
        } else {
            vuln.setVulnerableVersions(composerVulnerability.getAffectedVersions());
        }

        if (composerVulnerability.getSeverity() != null) {
            if (composerVulnerability.getSeverity().equalsIgnoreCase("CRITICAL")) {
                vuln.setSeverity(Severity.CRITICAL);
            } else if (composerVulnerability.getSeverity().equalsIgnoreCase("HIGH")) {
                vuln.setSeverity(Severity.HIGH);
            } else if (composerVulnerability.getSeverity().equalsIgnoreCase("MEDIUM")) {
                vuln.setSeverity(Severity.MEDIUM);
            } else if (composerVulnerability.getSeverity().equalsIgnoreCase("LOW")) {
                vuln.setSeverity(Severity.LOW);
            } else {
                vuln.setSeverity(Severity.UNASSIGNED);
            }
        } else {
            vuln.setSeverity(Severity.UNASSIGNED);
        }
        return vuln;
    }

    /**
     * Helper method that maps an GitHub Vulnerability object to a Dependency-Track VulnerableSoftware object.
     *
     * @param qm   a QueryManager
     * @param vuln the GitHub Vulnerability to map
     * @return a Dependency-Track VulnerableSoftware object
     */
    private List<VulnerableSoftware> mapVulnerabilityToVulnerableSoftware(final QueryManager qm, final ComposerVulnerability advisory) {
        final List<VulnerableSoftware> vsList = new ArrayList<>();
        try {
            final PackageURL purl = generatePurlFromComposerAdvisory(advisory);
            if (purl == null) return null;
            String versionStartIncluding = null;
            String versionStartExcluding = null;
            String versionEndIncluding = null;
            String versionEndExcluding = null;
            if (advisory.getAffectedVersions() != null) {
                // TODO Testcases for version ranges
                // Examples:
                //  "affectedVersions": ">=2.2,<2.2.10|>=2.3,<2.3.2-p2"
                //  "affectedVersions": <1.8.0 || >=2.2.0 <2.2.2 ">= 8.0.0 < 10.2.11 || >= 10.3.0 < 10.3.9 || >= 11.0.0 < 11.0.8"

                // regex splitters copied from Composer Version Parser
                LOGGER.trace("Parsing version ranges for " + advisory.getPackageEcosystem() + " : " + advisory.getPackageName() + " : " + advisory.getAffectedVersions());
                String[] ranges = Arrays.stream(advisory.getAffectedVersions().split("\\s*\\|\\|?\\s*")).map(String::trim).toArray(String[]::new);

                for (String range: ranges) {
                    // Split by both ',' and ' '
                    String[] parts = Arrays.stream(range.split("(?<!^|as|[=>< ,]) *(?<!-)[, ](?!-) *(?!,|as|$)")).map(String::trim).toArray(String[]::new);
                    for (String part : parts) {
                        if (part.startsWith(">=")) {
                            versionStartIncluding = part.replace(">=", "").trim();
                        } else if (part.startsWith(">")) {
                            versionStartExcluding = part.replace(">", "").trim();
                        } else if (part.startsWith("<=")) {
                            versionEndIncluding = part.replace("<=", "").trim();
                        } else if (part.startsWith("<")) {
                            versionEndExcluding = part.replace("<", "").trim();
                        } else if (part.startsWith("=")) {
                            versionStartIncluding = part.replace("=", "").trim();
                            versionEndIncluding = part.replace("=", "").trim();
                        } else {
                            //TODO Try to support all version ranges seen in Drupal package repo. All from packagist are supported above.
                            /* "<5.25.0 || 6.0.0 || 6.0.1" (no = for exact version)
                             * "*" (all versions, plugin marked as unsupported)
                             */
                            LOGGER.warn("Unable to determine version range of " + advisory.getPackageEcosystem()
                                    + " : " + advisory.getPackageName() + " : " + part);
                        }
                    }
                    VulnerableSoftware vs = qm.getVulnerableSoftwareByPurl(purl.getType(), purl.getNamespace(), purl.getName(),
                            versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding);
                    if (vs != null) {
                        if (!vsList.contains(vs)) {
                            vsList.add(vs);
                            continue;
                        }
                    }
                    vs = new VulnerableSoftware();
                    vs.setVulnerable(true);
                    vs.setPurlType(purl.getType());
                    vs.setPurlNamespace(purl.getNamespace());
                    vs.setPurlName(purl.getName());
                    vs.setPurl(purl.canonicalize());
                    vs.setVersionStartIncluding(versionStartIncluding);
                    vs.setVersionStartExcluding(versionStartExcluding);
                    vs.setVersionEndIncluding(versionEndIncluding);
                    vs.setVersionEndExcluding(versionEndExcluding);

                    vsList.add(vs);
                }
            }
            LOGGER.trace("Resulting VulnerableSoftware: " + vsList);
            return vsList;
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Unable to create purl from Composer Vulnerability. Skipping " + advisory.getPackageEcosystem() + " : " + advisory.getPackageName() + " for: " + advisory.getAdvisoryId());
        }
        return null;
    }

    private PackageURL generatePurlFromComposerAdvisory(final ComposerVulnerability vuln) throws MalformedPackageURLException {
            final String[] parts = vuln.getPackageName().split("/");
            final String namespace = String.join("/", Arrays.copyOfRange(parts, 0, parts.length - 1));
            return PackageURLBuilder.aPackageURL().withType(vuln.getPackageEcosystem()).withNamespace(namespace).withName(parts[parts.length - 1]).build();
    }

    protected void handleRequestException(final Logger logger, final Exception e) {
        logger.error("Request failure", e);
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.ANALYZER)
                .title(NotificationConstants.Title.ANALYZER_ERROR)
                .content("An error occurred while communicating with a vulnerability intelligence source. Check log for details. " + e.getMessage())
                .level(NotificationLevel.ERROR)
        );
    }
}
