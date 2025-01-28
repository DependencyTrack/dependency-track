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
package org.dependencytrack.tasks.repositories;

import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Map.Entry;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.event.ComposerAdvisoryMirrorEvent;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.Vulnerability.Source;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.composer.ComposerAdvisoryParser;
import org.dependencytrack.parser.composer.model.ComposerAdvisory;
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

    private boolean mirroredWithoutErrors = true;

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof ComposerAdvisoryMirrorEvent) {
            final long start = System.currentTimeMillis();
            LOGGER.info("Starting Composer Advisory mirroring task");

            try (final var qm = new QueryManager()) {
                for (final Repository repository : qm.getAllRepositoriesOrdered(RepositoryType.COMPOSER)) {
                        // Should we try catch all exceptions to make sure notification is sent?
                        mirroredWithoutErrors &= mirrorAdvisories(qm, repository);
                    }
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
                        .level(NotificationLevel.INFORMATIONAL));
            } else {
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.DATASOURCE_MIRRORING)
                        .title(NotificationConstants.Title.COMPOSER_ADVISORY_MIRROR)
                        .content(
                                "An error occurred mirroring the contents of Composer Advisories. Check log for details.")
                        .level(NotificationLevel.ERROR));
            }
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    protected boolean mirrorAdvisories(QueryManager qm, Repository repository) {
        if (!repository.isEnabled()) {
            return true;
        }
        boolean isAdvisoryMirroringEnabled = false;
        boolean isAliasSyncEnabled = false;

        if (repository.getConfig() != null) {
            final JSONObject config = new JSONObject(repository.getConfig());
            isAdvisoryMirroringEnabled = config
                    .optBoolean("advisoryMirroringEnabled", false);
            isAliasSyncEnabled = config
                    .optBoolean("advisoryAliasSyncEnabled", true);
            if (!isAdvisoryMirroringEnabled) {
                LOGGER.info(
                        "Advisory  mirroring is disabled for repository " + repository.getUrl());
            }
        }

        boolean result = true;
        // Vulnerability mirroring builds on the Composer meta analyzer
        // To avoid duplicating lots of code or having to extract alle common parts and
        // error handling, we just create an analyzer and let it do the work
        ComposerMetaAnalyzer composerMetaAnalyzer = new ComposerMetaAnalyzer();
        composerMetaAnalyzer.setRepositoryId(repository.getIdentifier());
        composerMetaAnalyzer.setRepositoryBaseUrl(repository.getUrl());
        composerMetaAnalyzer.setRepositoryUsernameAndPassword(repository.getUsername(), repository.getPassword());

        LOGGER.info("Mirorring Composer Advisories from " + repository.getUrl());
        JSONObject jsonAdvisories = composerMetaAnalyzer.retrieveAdvisories();

        if (jsonAdvisories == null) {
            return false;
        }

        final List<ComposerAdvisory> composerAdvisories = ComposerAdvisoryParser.parseAdvisoryFeed(jsonAdvisories);
        for (final ComposerAdvisory advisory : composerAdvisories) {
            result &= processAdvisory(qm, advisory, isAliasSyncEnabled);
        }

        return result;
    }

    /**
     * Synchronizes the Composer Advisories to the database.
     * @param qm
     * @param advisories  the advisories to synchronize
     * @param syncAliases
     */
    boolean processAdvisory(QueryManager qm, final ComposerAdvisory advisory, boolean syncAliases) {
        LOGGER.debug("Synchronizing Composer advisory: " + advisory.getAdvisoryId());

        final Vulnerability mappedVulnerability = mapComposerAdvisoryToVulnerability(advisory, syncAliases);
        final List<VulnerableSoftware> vsListOld = qm.detach(qm.getVulnerableSoftwareByVulnId(
                mappedVulnerability.getSource(), mappedVulnerability.getVulnId()));

        final Vulnerability existingVulnerability = qm.getVulnerabilityByVulnId(mappedVulnerability.getSource(),
                mappedVulnerability.getVulnId());

        final Vulnerability.Source vulnerabilitySource = Vulnerability.Source
                .valueOf(mappedVulnerability.getSource());

        Vulnerability synchronizedVulnerability = existingVulnerability;
        if (shouldUpdateExistingVulnerability(existingVulnerability, vulnerabilitySource)) {
            synchronizedVulnerability = qm.synchronizeVulnerability(mappedVulnerability, false);
            if (synchronizedVulnerability == null)
                return true;
        }

        if (syncAliases && mappedVulnerability.getAliases() != null && mappedVulnerability.getAliases().size() > 0) {
            for (VulnerabilityAlias alias : mappedVulnerability.getAliases()) {
                qm.synchronizeVulnerabilityAlias(alias);
            }
        }

        LOGGER.debug("Updating vulnerable software for advisory: " + advisory.getAdvisoryId());
        List<VulnerableSoftware> vsList = mapVulnerabilityToVulnerableSoftware(qm, advisory);
        qm.persist(vsList);
        final Vulnerability finalSynchronizedVulnerability = synchronizedVulnerability;
        final Vulnerability.Source attributionSource = vulnerabilitySource == Vulnerability.Source.DRUPAL? Vulnerability.Source.DRUPAL : Vulnerability.Source.COMPOSER;
        vsList.forEach(vs -> qm.updateAffectedVersionAttribution(finalSynchronizedVulnerability, vs,
            attributionSource));
        vsList = qm.reconcileVulnerableSoftware(synchronizedVulnerability, vsListOld, vsList,
            attributionSource);
        synchronizedVulnerability.setVulnerableSoftware(vsList);
        qm.persist(synchronizedVulnerability);
        return true;
    }

    private boolean shouldUpdateExistingVulnerability(Vulnerability existingVulnerability,
            Vulnerability.Source vulnerabilitySource) {
        /*
        * Compose Advisories can have their own Id (PKSA-xxxx-yyy) or an Id from an
        * authoritive source (CVE-xxxx-yyy, GHSA-xxxx-yyy, ...)
        * I haven't seen any Composer Advisory with a CVE or GHSA id, but it is
        * possible.
        *  Make sure that we don't overwrite data of the authoritative source
        * Similar to what is done for Osv Mirroring
        * Please note that Drupal is also considered authoritative source, but provided
        * by Composer here in this task
        */
        return (EnumSet.of(Vulnerability.Source.COMPOSER, Vulnerability.Source.DRUPAL).contains(vulnerabilitySource))
                || (existingVulnerability == null);
    }

    public static String extractVulnId(ComposerAdvisory composerAdvisory) {
        // Currently seen DRUPAL and COMPOSER, but for composer we need to look for other fields
        Source sourceFromId = Vulnerability.Source.resolve(composerAdvisory.getAdvisoryId());
        if (sourceFromId != null && !EnumSet.of(Vulnerability.Source.UNKNOWN, Vulnerability.Source.COMPOSER).contains(sourceFromId)) {
            return composerAdvisory.getAdvisoryId();
        }

        // Currently only used for GHSA and pointers to Friends Of PHP advisories, which is not a valid source
        Source sourceFromRemoteId = Vulnerability.Source.resolve(composerAdvisory.getRemoteId());
        if (sourceFromRemoteId != null && sourceFromRemoteId != Vulnerability.Source.UNKNOWN) {
            return composerAdvisory.getRemoteId();
        }

        // Some Advisories from Friends Of PHP have a GHSA, which is leading
        for (String possibleAlias : composerAdvisory.getSources().values()) {
            Source sourceFromPossibleAlias = Vulnerability.Source.resolve(possibleAlias);
            if (sourceFromPossibleAlias != null && sourceFromPossibleAlias != Vulnerability.Source.UNKNOWN) {
                return possibleAlias;
            }
        }

        // Use CVE, but ensure it's valid. You never know with these Composer repositories
        Source sourceFromCve = Vulnerability.Source.resolve(composerAdvisory.getCve());
        if (sourceFromCve != null && sourceFromCve == Vulnerability.Source.NVD) {
            return composerAdvisory.getCve();
        }

        // Wordt case will result in a PKSA as id, similar to OSV.
        return composerAdvisory.getAdvisoryId();
    }

    protected Vulnerability mapComposerAdvisoryToVulnerability(final ComposerAdvisory composerAdvisory, final boolean syncAliases) {
        final Vulnerability vuln = new Vulnerability();

        vuln.setVulnId(extractVulnId(composerAdvisory));
        vuln.setSource(Vulnerability.Source.resolve(vuln.getVulnId()));

        String description = composerAdvisory.getTitle() + " in " + composerAdvisory.getPackageName() + " "
                + composerAdvisory.getAffectedVersions() + "\n\n";
        List<String> references = new ArrayList<>();
        references.add(composerAdvisory.getLink());
        for (Entry<String, String> source : composerAdvisory.getSources().entrySet()) {
            if (source.getKey().equalsIgnoreCase("github")) {
                references.add("https://github.com/advisories/" + source.getValue());
            } else if (source.getKey().equalsIgnoreCase("friendsofphp/security-advisories")) {
                references.add("https://github.com/FriendsOfPHP/security-advisories/blob/master/" + source.getValue());
            } else {
                description += "\nUnmapped source: " + source.getKey() + " : " + source.getValue() + "\n";
            }
        }
        references.add(composerAdvisory.getComposerRepository());

        if (!references.isEmpty()) {
            final StringBuilder sb = new StringBuilder();
            for (String ref : references) {
                // Convert reference to Markdown format;
                sb.append("* [").append(ref).append("](").append(ref).append(")\n");
            }
            vuln.setReferences(sb.toString());
        }

        vuln.setDescription(description);
        vuln.setTitle(StringUtils.abbreviate(composerAdvisory.getTitle(), "...", 255));
        if (composerAdvisory.getReportedAt() != null) {
            vuln.setPublished(Date.from(composerAdvisory.getReportedAt().toInstant(ZoneOffset.UTC)));
            // Should we leave Updated null?
            vuln.setUpdated(Date.from(composerAdvisory.getReportedAt().toInstant(ZoneOffset.UTC)));
        }

        if (composerAdvisory.getAffectedVersions() != null
                && composerAdvisory.getAffectedVersions().length() > 255) {
            // https://github.com/DependencyTrack/dependency-track/issues/4512
            LOGGER.warn("Affected versions for " + composerAdvisory.getAdvisoryId()
                    + " is too long. Truncating to 255 characters.");
            vuln.setVulnerableVersions(StringUtils.abbreviate(composerAdvisory.getAffectedVersions(), "...", 255));
        } else {
            vuln.setVulnerableVersions(composerAdvisory.getAffectedVersions());
        }

        if (composerAdvisory.getSeverity() != null) {
            if (composerAdvisory.getSeverity().equalsIgnoreCase("CRITICAL")) {
                vuln.setSeverity(Severity.CRITICAL);
            } else if (composerAdvisory.getSeverity().equalsIgnoreCase("HIGH")) {
                vuln.setSeverity(Severity.HIGH);
            } else if (composerAdvisory.getSeverity().equalsIgnoreCase("MEDIUM")) {
                vuln.setSeverity(Severity.MEDIUM);
            } else if (composerAdvisory.getSeverity().equalsIgnoreCase("LOW")) {
                vuln.setSeverity(Severity.LOW);
            } else {
                vuln.setSeverity(Severity.UNASSIGNED);
            }
        } else {
            vuln.setSeverity(Severity.UNASSIGNED);
        }

        if (syncAliases) {
            VulnerabilityAlias alias = new VulnerabilityAlias();
            alias.setAliasFromVulnId(vuln.getVulnId());
            alias.setAliasFromVulnId(composerAdvisory.getCve());
            alias.setAliasFromVulnId(composerAdvisory.getRemoteId());
            for (String possibleAlias : composerAdvisory.getSources().values()) {
                alias.setAliasFromVulnId(possibleAlias);
            }

            if (alias.countIdentifiers() > 1) {
                vuln.setAliases(List.of(alias));
            }
        }

        return vuln;
    }

    /**
     * Helper method that maps an GitHub Vulnerability object to a Dependency-Track
     * VulnerableSoftware object.
     *
     * @param qm   a QueryManager
     * @param vuln the GitHub Vulnerability to map
     * @return a Dependency-Track VulnerableSoftware object
     */
    protected List<VulnerableSoftware> mapVulnerabilityToVulnerableSoftware(final QueryManager qm,
            final ComposerAdvisory advisory) {
        final List<VulnerableSoftware> vsList = new ArrayList<>();
        try {
            final PackageURL purl = generatePurlFromComposerAdvisory(advisory);
            if (purl == null)
                return null;

            if (advisory.getAffectedVersions() != null) {
                // regex splitters copied from Composer Version Parser
                LOGGER.trace("Parsing version ranges for " + advisory.getPackageEcosystem() + " : "
                        + advisory.getPackageName() + " : " + advisory.getAffectedVersions());
                String[] ranges = Arrays.stream(advisory.getAffectedVersions().split("\\s*\\|\\|?\\s*"))
                        .map(String::trim).toArray(String[]::new);

                for (String range : ranges) {
                    String versionStartIncluding = null;
                    String versionStartExcluding = null;
                    String versionEndIncluding = null;
                    String versionEndExcluding = null;
                    // Split by both ',' and ' '
                    String[] parts = Arrays.stream(range.split("(?<!^|as|[=>< ,]) *(?<!-)[, ](?!-) *(?!,|as|$)"))
                            .map(String::trim).toArray(String[]::new);
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
                        } else if (part.trim().equals("*")) {
                            // Drupal sometimes uses * to indicate all versions are vulnerable for abandoned plugins
                            // Since we don't have a "deprecated" or "endoflife" or "unsupported" or "abandoned" flag, we do this:
                            versionEndExcluding = "999.999.999";
                        } else {
                            // No operator, so it's a single version. Or garbage. But since none of the parts are checked for formatting, we don't check neither
                            // Drupal uses this, for example "8.1.0"
                            versionStartIncluding = part;
                            versionEndIncluding = part;
                        }
                    }
                    VulnerableSoftware vs = qm.getVulnerableSoftwareByPurl(purl.getType(), purl.getNamespace(), purl.getName(), purl.getVersion(),
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
            LOGGER.warn("Unable to create purl from Composer Vulnerability. Skipping " + advisory.getPackageEcosystem()
                    + " : " + advisory.getPackageName() + " for: " + advisory.getAdvisoryId());
        }
        return null;
    }

    private PackageURL generatePurlFromComposerAdvisory(final ComposerAdvisory vuln)
            throws MalformedPackageURLException {
        final String[] parts = vuln.getPackageName().split("/");
        final String namespace = String.join("/", Arrays.copyOfRange(parts, 0, parts.length - 1));
        return PackageURLBuilder.aPackageURL().withType(vuln.getPackageEcosystem()).withNamespace(namespace)
                .withName(parts[parts.length - 1]).build();
    }

    protected void handleRequestException(final Logger logger, final Exception e) {
        logger.error("Request failure", e);
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.ANALYZER)
                .title(NotificationConstants.Title.ANALYZER_ERROR)
                .content(
                        "An error occurred while communicating with a vulnerability intelligence source. Check log for details. "
                                + e.getMessage())
                .level(NotificationLevel.ERROR));
    }
}
