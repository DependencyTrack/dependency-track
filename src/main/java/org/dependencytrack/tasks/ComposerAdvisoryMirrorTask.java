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

import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.ComposerAdvisoryMirrorEvent;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.composer.ComposerSecurityAdvisoryParser;
import org.dependencytrack.parser.composer.model.ComposerSecurityVulnerability;
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
    // private static final String COMPOSER_SECURITY_API = "https://packagist.org/api/security-advisories/?updatedSince=100";
    private static final String COMPOSER_SECURITY_API = "https://packages.drupal.org/8/security-advisories?updatedSince=100";



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
        //TODO
        LOGGER.info("Starting Composer Advisory mirroring taskVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV");
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
                final List<ComposerSecurityVulnerability> advisories = parser.parse(jsonObject);
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
    void updateDatasource(final List<ComposerSecurityVulnerability> advisories) {
        LOGGER.debug("Updating datasource with Composer advisories");
        try (QueryManager qm = new QueryManager()) {
            for (final ComposerSecurityVulnerability advisory : advisories) {
                LOGGER.debug("Synchronizing Composer advisory: " + advisory.getAdvisoryId());

                final Vulnerability mappedVulnerability = mapComposerVulnerabilityToVulnerability(qm, advisory);
                final List<VulnerableSoftware> vsListOld = qm.detach(qm.getVulnerableSoftwareByVulnId(mappedVulnerability.getSource(), mappedVulnerability.getVulnId()));

                // final Vulnerability synchronizedVulnerability = qm.synchronizeVulnerability(mappedVulnerability, false);

                // if (synchronizedVulnerability == null) continue;
                List<VulnerableSoftware> vsList = mapVulnerabilityToVulnerableSoftware(qm, advisory);
                // TODO ALIAS SYNC
                // if (isAliasSyncEnabled) {
                //     for (Pair<String, String> identifier : advisory.getIdentifiers()) {
                //         if (identifier != null && identifier.getLeft() != null
                //                 && "CVE".equalsIgnoreCase(identifier.getLeft()) && identifier.getLeft().startsWith("CVE")) {
                //             LOGGER.debug("Updating vulnerability alias for " + advisory.getGhsaId());
                //             final VulnerabilityAlias alias = new VulnerabilityAlias();
                //             alias.setGhsaId(advisory.getGhsaId());
                //             alias.setCveId(identifier.getRight());
                //             qm.synchronizeVulnerabilityAlias(alias);
                //         }
                //     }
                // }
                LOGGER.debug("Updating vulnerable software for advisory: " + advisory.getAdvisoryId());
                // qm.persist(vsList);
                // vsList.forEach(vs -> qm.updateAffectedVersionAttribution(synchronizedVulnerability, vs, Vulnerability.Source.COMPOSER));
                // vsList = qm.reconcileVulnerableSoftware(synchronizedVulnerability, vsListOld, vsList, Vulnerability.Source.COMPOSER);
                // synchronizedVulnerability.setVulnerableSoftware(vsList);
                // qm.persist(synchronizedVulnerability);
            }
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    /**
     * Helper method that maps an GitHub SecurityAdvisory object to a Dependency-Track vulnerability object.
     *
     * @param vulnerability the GitHub SecurityAdvisory to map
     * @return a Dependency-Track Vulnerability object
     */
    private Vulnerability mapComposerVulnerabilityToVulnerability(final QueryManager qm, final ComposerSecurityVulnerability vulnerability) {
        final Vulnerability vuln = new Vulnerability();
        //TODO MAP Known sources
        vuln.setSource(Vulnerability.Source.COMPOSER);
        vuln.setVulnId(vulnerability.getAdvisoryId());

        vuln.setDescription("Composer repository: %s".formatted(vulnerability.getComposerRepository()));
        vuln.setTitle(vulnerability.getTitle());
        if (vulnerability.getReportedAt() != null) {
            vuln.setPublished(Date.from(vulnerability.getReportedAt().toInstant(ZoneOffset.UTC)));
            // Should we leave Updated null?
            vuln.setUpdated(Date.from(vulnerability.getReportedAt().toInstant(ZoneOffset.UTC)));
        }
        vuln.setReferences(vulnerability.getLink());

        vuln.setVulnerableVersions(vulnerability.getAffectedVersions());

        if (vulnerability.getSeverity() != null) {
            if (vulnerability.getSeverity().equalsIgnoreCase("CRITICAL")) {
                vuln.setSeverity(Severity.CRITICAL);
            } else if (vulnerability.getSeverity().equalsIgnoreCase("HIGH")) {
                vuln.setSeverity(Severity.HIGH);
            } else if (vulnerability.getSeverity().equalsIgnoreCase("MEDIUM")) {
                vuln.setSeverity(Severity.MEDIUM);
            } else if (vulnerability.getSeverity().equalsIgnoreCase("LOW")) {
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
    private List<VulnerableSoftware> mapVulnerabilityToVulnerableSoftware(final QueryManager qm, final ComposerSecurityVulnerability advisory) {
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
                        continue;
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

    private PackageURL generatePurlFromComposerAdvisory(final ComposerSecurityVulnerability vuln) throws MalformedPackageURLException {
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
