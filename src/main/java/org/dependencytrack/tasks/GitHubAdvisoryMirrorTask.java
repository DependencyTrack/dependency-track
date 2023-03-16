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

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.GitHubAdvisoryMirrorEvent;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.github.graphql.GitHubSecurityAdvisoryParser;
import org.dependencytrack.parser.github.graphql.model.GitHubSecurityAdvisory;
import org.dependencytrack.parser.github.graphql.model.GitHubVulnerability;
import org.dependencytrack.parser.github.graphql.model.PageableList;
import org.dependencytrack.persistence.QueryManager;
import org.json.JSONObject;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.template.PebbleTemplate;

public class GitHubAdvisoryMirrorTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(GitHubAdvisoryMirrorTask.class);
    private static final PebbleEngine ENGINE = new PebbleEngine.Builder().build();
    private static final PebbleTemplate TEMPLATE = ENGINE.getTemplate("templates/github/securityAdvisories.peb");
    private static final String GITHUB_GRAPHQL_URL = "https://api.github.com/graphql";

    private final boolean isEnabled;
    private String accessToken;
    private boolean mirroredWithoutErrors = true;

    public GitHubAdvisoryMirrorTask() {
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getGroupName(), VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getPropertyName());
            this.isEnabled = enabled != null && Boolean.parseBoolean(enabled.getPropertyValue());

            final ConfigProperty accessToken = qm.getConfigProperty(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN.getGroupName(), VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN.getPropertyName());
            if (accessToken != null) {
                this.accessToken = accessToken.getPropertyValue();
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof GitHubAdvisoryMirrorEvent && this.isEnabled) {
            if (this.accessToken != null) {
                final long start = System.currentTimeMillis();
                LOGGER.info("Starting GitHub Advisory mirroring task");
                try {
                    retrieveAdvisories(null);
                } catch (IOException ex) {
                    handleRequestException(LOGGER, ex);
                }
                final long end = System.currentTimeMillis();
                LOGGER.info("GitHub Advisory mirroring complete");
                LOGGER.info("Time spent (total): " + (end - start) + "ms");
            } else {
                LOGGER.warn("GitHub Advisory mirroring is enabled, but no personal access token is configured. Skipping.");
            }
        }
    }

    private String generateQueryTemplate(final String advisoriesEndCursor) {
        final Map<String, Object> context = new HashMap<>();
        context.put("paginationAdvisories", 100);
        context.put("paginationVulnerabilities", 10);
        if (advisoriesEndCursor != null) {
            context.put("advisoriesEndCursor", advisoriesEndCursor);
        }
        try (final Writer writer = new StringWriter()) {
            TEMPLATE.evaluate(writer, context);
            return writer.toString();
        } catch (IOException e) {
            Logger.getLogger(this.getClass()).error("An error was encountered evaluating template", e);
            return null;
        }
    }

    private void retrieveAdvisories(final String advisoriesEndCursor) throws IOException {
        final String queryTemplate = generateQueryTemplate(advisoriesEndCursor);
        HttpPost request = new HttpPost(GITHUB_GRAPHQL_URL);
        request.addHeader("Authorization", "bearer " + accessToken);
        request.addHeader("content-type", "application/json");
        request.addHeader("accept", "application/json");
        var jsonBody = new JSONObject();
        jsonBody.put("query", queryTemplate);
        var stringEntity = new StringEntity(jsonBody.toString());
        request.setEntity(stringEntity);
        try (CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            if (response.getStatusLine().getStatusCode() < HttpStatus.SC_OK || response.getStatusLine().getStatusCode() >= HttpStatus.SC_MULTIPLE_CHOICES) {
                LOGGER.error("An error was encountered retrieving advisories with HTTP Status : " + response.getStatusLine().getStatusCode() + " " + response.getStatusLine().getReasonPhrase());
                LOGGER.debug(queryTemplate);
                mirroredWithoutErrors = false;
            } else {
                var parser = new GitHubSecurityAdvisoryParser();
                String responseString = EntityUtils.toString(response.getEntity());
                var jsonObject = new JSONObject(responseString);
                final PageableList pageableList = parser.parse(jsonObject);
                updateDatasource(pageableList.getAdvisories());
                if (pageableList.isHasNextPage()) {
                    retrieveAdvisories(pageableList.getEndCursor());
                }
            }

            if (mirroredWithoutErrors) {
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.DATASOURCE_MIRRORING)
                        .title(NotificationConstants.Title.GITHUB_ADVISORY_MIRROR)
                        .content("Mirroring of GitHub Advisories completed successfully")
                        .level(NotificationLevel.INFORMATIONAL)
                );
            } else {
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.DATASOURCE_MIRRORING)
                        .title(NotificationConstants.Title.GITHUB_ADVISORY_MIRROR)
                        .content("An error occurred mirroring the contents of GitHub Advisories. Check log for details.")
                        .level(NotificationLevel.ERROR)
                );
            }
        }
    }

    /**
     * Synchronizes the advisories that were downloaded with the internal Dependency-Track database.
     *
     * @param advisories the results to synchronize
     */
    void updateDatasource(final List<GitHubSecurityAdvisory> advisories) {
        LOGGER.debug("Updating datasource with GitHub advisories");
        try (QueryManager qm = new QueryManager().withL2CacheDisabled()) {
            for (final GitHubSecurityAdvisory advisory : advisories) {
                LOGGER.debug("Synchronizing GitHub advisory: " + advisory.getGhsaId());
                final Vulnerability mappedVulnerability = mapAdvisoryToVulnerability(qm, advisory);
                final List<VulnerableSoftware> vsListOld = qm.detach(qm.getVulnerableSoftwareByVulnId(mappedVulnerability.getSource(), mappedVulnerability.getVulnId()));
                final Vulnerability synchronizedVulnerability = qm.synchronizeVulnerability(mappedVulnerability, false);
                List<VulnerableSoftware> vsList = new ArrayList<>();
                for (GitHubVulnerability ghvuln : advisory.getVulnerabilities()) {
                    final VulnerableSoftware vs = mapVulnerabilityToVulnerableSoftware(qm, ghvuln, advisory);
                    if (vs != null) {
                        vsList.add(vs);
                    }
                    for (Pair<String, String> identifier : advisory.getIdentifiers()) {
                        if (identifier != null && identifier.getLeft() != null
                                && "CVE" .equalsIgnoreCase(identifier.getLeft()) && identifier.getLeft().startsWith("CVE")) {
                            LOGGER.debug("Updating vulnerability alias for " + advisory.getGhsaId());
                            final VulnerabilityAlias alias = new VulnerabilityAlias();
                            alias.setGhsaId(advisory.getGhsaId());
                            alias.setCveId(identifier.getRight());
                            qm.synchronizeVulnerabilityAlias(alias);
                        }
                    }
                }
                LOGGER.debug("Updating vulnerable software for advisory: " + advisory.getGhsaId());
                qm.persist(vsList);
                vsList.forEach(vs -> qm.updateAffectedVersionAttribution(synchronizedVulnerability, vs, Vulnerability.Source.GITHUB));
                vsList = qm.reconcileVulnerableSoftware(synchronizedVulnerability, vsListOld, vsList, Vulnerability.Source.GITHUB);
                synchronizedVulnerability.setVulnerableSoftware(vsList);
                qm.persist(synchronizedVulnerability);
            }
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    /**
     * Helper method that maps an GitHub SecurityAdvisory object to a Dependency-Track vulnerability object.
     *
     * @param advisory the GitHub SecurityAdvisory to map
     * @return a Dependency-Track Vulnerability object
     */
    private Vulnerability mapAdvisoryToVulnerability(final QueryManager qm, final GitHubSecurityAdvisory advisory) {
        final Vulnerability vuln = new Vulnerability();
        vuln.setSource(Vulnerability.Source.GITHUB);
        vuln.setVulnId(String.valueOf(advisory.getGhsaId()));
        vuln.setDescription(advisory.getDescription());
        vuln.setTitle(advisory.getSummary());
        vuln.setPublished(Date.from(advisory.getPublishedAt().toInstant()));
        vuln.setUpdated(Date.from(advisory.getUpdatedAt().toInstant()));

        if (advisory.getReferences() != null && advisory.getReferences().size() > 0) {
            final StringBuilder sb = new StringBuilder();
            for (String ref : advisory.getReferences()) {
                // Convert reference to Markdown format;
                sb.append("* [").append(ref).append("](").append(ref).append(")\n");
            }
            vuln.setReferences(sb.toString());
        }

        //vuln.setVulnerableVersions(advisory.getVulnerableVersions());
        //vuln.setPatchedVersions(advisory.getPatchedVersions());
        if (advisory.getCwes() != null) {
            for (int i = 0; i < advisory.getCwes().size(); i++) {
                final Cwe cwe = CweResolver.getInstance().resolve(qm, advisory.getCwes().get(i));
                if (cwe != null) {
                    vuln.addCwe(cwe);
                }
            }
        }

        if (advisory.getSeverity() != null) {
            if (advisory.getSeverity().equalsIgnoreCase("CRITICAL")) {
                vuln.setSeverity(Severity.CRITICAL);
            } else if (advisory.getSeverity().equalsIgnoreCase("HIGH")) {
                vuln.setSeverity(Severity.HIGH);
            } else if (advisory.getSeverity().equalsIgnoreCase("MODERATE")) {
                vuln.setSeverity(Severity.MEDIUM);
            } else if (advisory.getSeverity().equalsIgnoreCase("LOW")) {
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
    private VulnerableSoftware mapVulnerabilityToVulnerableSoftware(final QueryManager qm, final GitHubVulnerability vuln, final GitHubSecurityAdvisory advisory) {
        try {
            final PackageURL purl = generatePurlFromGitHubVulnerability(vuln);
            if (purl == null) return null;
            String versionStartIncluding = null;
            String versionStartExcluding = null;
            String versionEndIncluding = null;
            String versionEndExcluding = null;
            if (vuln.getVulnerableVersionRange() != null) {
                final String[] parts = Arrays.stream(vuln.getVulnerableVersionRange().split(",")).map(String::trim).toArray(String[]::new);
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
                        LOGGER.warn("Unable to determine version range of " + vuln.getPackageEcosystem()
                                + " : " + vuln.getPackageName() + " : " + vuln.getVulnerableVersionRange());
                    }
                }
            }
            VulnerableSoftware vs = qm.getVulnerableSoftwareByPurl(purl.getType(), purl.getNamespace(), purl.getName(),
                    versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding);
            if (vs != null) {
                return vs;
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
            return vs;
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Unable to create purl from GitHub Vulnerability. Skipping " + vuln.getPackageEcosystem() + " : " + vuln.getPackageName() + " for: " + advisory.getGhsaId());
        }
        return null;
    }

    /**
     * Map GitHub ecosystem to PackageURL type
     *
     * @param ecosystem GitHub ecosystem
     * @return the PackageURL for the ecosystem
     * @see https://github.com/github/advisory-database
     */
    private String mapGitHubEcosystemToPurlType(final String ecosystem) {
        switch (ecosystem.toUpperCase()) {
            case "MAVEN":
                return PackageURL.StandardTypes.MAVEN;
            case "RUST":
                return PackageURL.StandardTypes.CARGO;
            case "PIP":
                return PackageURL.StandardTypes.PYPI;
            case "RUBYGEMS":
                return PackageURL.StandardTypes.GEM;
            case "GO":
                return PackageURL.StandardTypes.GOLANG;
            case "NPM":
                return PackageURL.StandardTypes.NPM;
            case "COMPOSER":
                return PackageURL.StandardTypes.COMPOSER;
            case "NUGET":
                return PackageURL.StandardTypes.NUGET;
            default:
                return null;
        }
    }

    private PackageURL generatePurlFromGitHubVulnerability(final GitHubVulnerability vuln) throws MalformedPackageURLException {
        final String purlType = mapGitHubEcosystemToPurlType(vuln.getPackageEcosystem());
        if (purlType != null) {
            if (PackageURL.StandardTypes.NPM.equals(purlType) && vuln.getPackageName().contains("/")) {
                final String[] parts = vuln.getPackageName().split("/");
                return PackageURLBuilder.aPackageURL().withType(purlType).withNamespace(parts[0]).withName(parts[1]).build();
            } else if (PackageURL.StandardTypes.MAVEN.equals(purlType) && vuln.getPackageName().contains(":")) {
                final String[] parts = vuln.getPackageName().split(":");
                return PackageURLBuilder.aPackageURL().withType(purlType).withNamespace(parts[0]).withName(parts[1]).build();
            } else if (Set.of(PackageURL.StandardTypes.COMPOSER, PackageURL.StandardTypes.GOLANG).contains(purlType) && vuln.getPackageName().contains("/")) {
                final String[] parts = vuln.getPackageName().split("/");
                final String namespace = String.join("/", Arrays.copyOfRange(parts, 0, parts.length - 1));
                return PackageURLBuilder.aPackageURL().withType(purlType).withNamespace(namespace).withName(parts[parts.length - 1]).build();
            } else {
                return PackageURLBuilder.aPackageURL().withType(purlType).withName(vuln.getPackageName()).build();
            }
        }
        return null;
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
