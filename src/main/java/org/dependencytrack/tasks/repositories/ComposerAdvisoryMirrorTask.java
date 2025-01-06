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
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
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
                    if (repository.isEnabled()) {
                        if (repository.getConfig() != null) {
                            final JSONObject config = new JSONObject(repository.getConfig());
                            final boolean isAdvisoryMirroringEnabled = config
                                    .optBoolean("advisoryMirroringEnabled", false);
                            final boolean isAliasSyncEnabled = config
                                    .optBoolean("advisoryAliasSyncEnabled", true);
                            if (!isAdvisoryMirroringEnabled) {
                                LOGGER.info(
                                        "Advisory  mirroring is disabled for repository " + repository.getUrl());
                            }
                            // Should we try catch all exceptions to make sure notification is sent?
                            mirroredWithoutErrors &= mirrorAdvisories(repository,
                                    isAliasSyncEnabled);
                        }
                    }
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

    private boolean mirrorAdvisories(Repository repository, boolean syncAliases) {
        boolean result = true;
        // Vulnerability mirroring builds on the Composer meta analyzer
        // To avoid duplicating lots of code or having to extract alle common parts and
        // error handling, we just create an analyzer and let it do the work
        ComposerMetaAnalyzer composerMetaAnalyzer = new ComposerMetaAnalyzer();
        composerMetaAnalyzer.setRepositoryId(repository.getIdentifier());
        composerMetaAnalyzer.setRepositoryBaseUrl(repository.getUrl());
        composerMetaAnalyzer.setRepositoryUsernameAndPassword(repository.getUsername(), repository.getPassword());

        LOGGER.info("Updating datasource with Composer advisories from " + repository.getUrl());
        JSONObject jsonAdvisories = composerMetaAnalyzer.retrieveAdvisories();

        if (jsonAdvisories == null) {
            return false;
        }
        var parser = new ComposerAdvisoryParser();
        final List<ComposerAdvisory> composerAdvisories = parser.parseAdvisoryFeed(jsonAdvisories);
        try (QueryManager qm = new QueryManager()) {
            for (final ComposerAdvisory advisory : composerAdvisories) {
                result &= processAdvisory(qm, advisory, syncAliases);
            }
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

        final Vulnerability mappedVulnerability = mapComposerAdvisoryToVulnerability(advisory);
        final List<VulnerableSoftware> vsListOld = qm.detach(qm.getVulnerableSoftwareByVulnId(
                mappedVulnerability.getSource(), mappedVulnerability.getVulnId()));

        final Vulnerability existingVulnerability = qm.getVulnerabilityByVulnId(mappedVulnerability.getSource(),
                mappedVulnerability.getVulnId());

        final Vulnerability.Source vulnerabilitySource = Vulnerability.Source
                .valueOf(mappedVulnerability.getSource());

        // Compose Advisories can have their own Id (PKSA-xxxx-yyy) or an Id from an
        // authoritive source (CVE-xxxx-yyy, GHSA-xxxx-yyy, ...)
        // I haven't seen any Composer Advisory with a CVE or GHSA id, but it is
        // possible.
        // Make sure that we don't overwrite data of the authoritative source
        // Similar to what is done for Osv Mirroring
        // Please note that Drupal is also considered authoritative source, but provided
        // by Composer here in this task

        final ConfigPropertyConstants vulnAuthoritativeSourceToggle = switch (vulnerabilitySource) {
            case Vulnerability.Source.NVD -> ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;
            case Vulnerability.Source.GITHUB ->
                ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;
            default -> null;
        };

        final boolean vulnAuthoritativeSourceEnabled = vulnAuthoritativeSourceToggle == null ? true
                : Boolean
                        .valueOf(qm.getConfigProperty(vulnAuthoritativeSourceToggle.getGroupName(),
                                vulnAuthoritativeSourceToggle.getPropertyName()).getPropertyValue());
        Vulnerability synchronizedVulnerability = existingVulnerability;
        //TODO VS Only store vulnerabilities that don't have a CVE or GHSA id? plus Drupal maybe? To avoid lots of aliases for the same vulnz
        if (shouldUpdateExistingVulnerability(existingVulnerability, vulnerabilitySource,
                vulnAuthoritativeSourceEnabled)) {
            synchronizedVulnerability = qm.synchronizeVulnerability(mappedVulnerability, false);
            if (synchronizedVulnerability == null)
                return true;
            // TODO what if aliases haved changed? This doesn't get detected currently by
            // other mirroring tasks either
        }

        if (syncAliases) {
            VulnerabilityAlias alias = extractAliases(advisory);
            if (alias != null) {
                qm.synchronizeVulnerabilityAlias(alias);
            }
        }

        LOGGER.debug("Updating vulnerable software for advisory: " + advisory.getAdvisoryId());
        List<VulnerableSoftware> vsList = mapVulnerabilityToVulnerableSoftware(qm, advisory);
        qm.persist(vsList);
        final Vulnerability finalSynchronizedVulnerability = synchronizedVulnerability;
        //TODO VS make sure only DRUPAL or COMPOSER is used as attribution source
        vsList.forEach(vs -> qm.updateAffectedVersionAttribution(finalSynchronizedVulnerability, vs,
                vulnerabilitySource));
        vsList = qm.reconcileVulnerableSoftware(synchronizedVulnerability, vsListOld, vsList,
                vulnerabilitySource);
        synchronizedVulnerability.setVulnerableSoftware(vsList);
        qm.persist(synchronizedVulnerability);
        return true;
    }

    private boolean shouldUpdateExistingVulnerability(Vulnerability existingVulnerability,
            Vulnerability.Source vulnerabilitySource, boolean vulnAuthoritativeSourceEnabled) {
        // Should we just skip anything other than DRUPAL and COMPOSER? Composer repositories are only providing limit information
        // Composeris (in DT) the authoritative source for Drupal
        return (EnumSet.of(Vulnerability.Source.COMPOSER, Vulnerability.Source.DRUPAL).contains(vulnerabilitySource))
                || (existingVulnerability == null) // Vuln is not replicated yet or declared by authoritative source with appropriate state
                || (existingVulnerability != null && !vulnAuthoritativeSourceEnabled); // Vuln has been replicated but authoritative source is disabled
    }

    public static Vulnerability.Source extractSource(ComposerAdvisory composerAdvisory) {
        if (composerAdvisory.getAdvisoryId().startsWith("SA-CORE")
                || composerAdvisory.getAdvisoryId().startsWith("SA-CONTRIB")) {
            return Vulnerability.Source.DRUPAL;
        } else {
            return Vulnerability.Source.COMPOSER;
        }
    }

    private VulnerabilityAlias extractAliases(ComposerAdvisory composerAdvisory) {
        // We only support one alias per source and do not store effectively alias
        // records
        VulnerabilityAlias alias = new VulnerabilityAlias();
        // Make sure we set DrupalId or ComposerId depending on AdvisoryId
        alias.setAliasFromVulnId(composerAdvisory.getAdvisoryId());
        boolean aliasesPresent = false;
        aliasesPresent |= alias.setAliasFromVulnId(composerAdvisory.getCve());
        aliasesPresent |= alias.setAliasFromVulnId(composerAdvisory.getRemoteId());
        for (String possibleAlias : composerAdvisory.getSources().values()) {
            aliasesPresent |= alias.setAliasFromVulnId(possibleAlias);
        }
        if (aliasesPresent) {
            return alias;
        }
        return null;
    }

    protected Vulnerability mapComposerAdvisoryToVulnerability(final ComposerAdvisory composerAdvisory) {
        final Vulnerability vuln = new Vulnerability();

        vuln.setVulnId(composerAdvisory.getAdvisoryId());
        vuln.setSource(extractSource(composerAdvisory));

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
            String versionStartIncluding = null;
            String versionStartExcluding = null;
            String versionEndIncluding = null;
            String versionEndExcluding = null;
            if (advisory.getAffectedVersions() != null) {
                // TODO VS Testcases for version ranges
                // Examples:
                // "affectedVersions": ">=2.2,<2.2.10|>=2.3,<2.3.2-p2"
                // "affectedVersions": <1.8.0 || >=2.2.0 <2.2.2 ">= 8.0.0 < 10.2.11 || >= 10.3.0
                // < 10.3.9 || >= 11.0.0 < 11.0.8"

                // regex splitters copied from Composer Version Parser
                LOGGER.trace("Parsing version ranges for " + advisory.getPackageEcosystem() + " : "
                        + advisory.getPackageName() + " : " + advisory.getAffectedVersions());
                String[] ranges = Arrays.stream(advisory.getAffectedVersions().split("\\s*\\|\\|?\\s*"))
                        .map(String::trim).toArray(String[]::new);

                for (String range : ranges) {
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
                        } else {
                            // TODO VS Try to support all version ranges seen in Drupal package repo. All
                            // from
                            // packagist are supported above.
                            /*
                             * "<5.25.0 || 6.0.0 || 6.0.1" (no = for exact version)
                             * "*" (all versions, plugin marked as unsupported)
                             */
                            LOGGER.warn("Unable to determine version range of " + advisory.getPackageEcosystem()
                                    + " : " + advisory.getPackageName() + " : " + part);
                        }
                    }
                    VulnerableSoftware vs = qm.getVulnerableSoftwareByPurl(purl.getType(), purl.getNamespace(),
                            purl.getName(),
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
