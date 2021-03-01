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

import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.UnirestException;
import kong.unirest.UnirestInstance;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.NpmAdvisoryMirrorEvent;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.npm.NpmAdvisoriesParser;
import org.dependencytrack.parser.npm.model.Advisory;
import org.dependencytrack.parser.npm.model.AdvisoryResults;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.DateUtil;
import java.util.Date;

/**
 * Subscriber task that performs a mirror of NPM public advisories.
 *
 * @author Steve Springett
 * @since 3.2.1
 */
public class NpmAdvisoryMirrorTask implements LoggableSubscriber {

    private static final String NPM_BASE_URL = "https://registry.npmjs.org";
    private static final String NPM_ADVISORY_START = "/-/npm/v1/security/advisories";
    private static final Logger LOGGER = Logger.getLogger(NpmAdvisoryMirrorTask.class);

    private boolean successful = true;

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof NpmAdvisoryMirrorEvent) {
            LOGGER.info("Starting NPM advisory mirroring task");
            getAdvisories();
            LOGGER.info("NPM advisory mirroring complete");
            if (successful) {
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.DATASOURCE_MIRRORING)
                        .title(NotificationConstants.Title.NPM_ADVISORY_MIRROR)
                        .content("Mirroring of the NPM Advisory data completed successfully")
                        .level(NotificationLevel.INFORMATIONAL)
                );
            }
        }
    }

    /**
     * Performs an incremental mirror (using pagination) of the NPM public advisory database.
     */
    private void getAdvisories() {
        final Date currentDate = new Date();
        LOGGER.info("Retrieving NPM advisories at " + currentDate);

        try {
            final UnirestInstance ui = UnirestFactory.getUnirestInstance();

            int firstAdvisory = -1;
            boolean more = true;

            String url = NPM_BASE_URL + NPM_ADVISORY_START;
            while (more) {
                LOGGER.info("Retrieving NPM advisories from " + url);
                final HttpResponse<JsonNode> jsonResponse = ui.get(url)
                        .header("accept", "application/json")
                        .asJson();

                if (jsonResponse.getStatus() == 200) {
                    final NpmAdvisoriesParser parser = new NpmAdvisoriesParser();
                    final AdvisoryResults results = parser.parse(jsonResponse.getBody());

                    if (results.getAdvisories() != null && results.getAdvisories().size() > 0) {
                        if (firstAdvisory == -1) {
                            firstAdvisory = results.getAdvisories().get(0).getId();
                        } else if (firstAdvisory == results.getAdvisories().get(0).getId()){
                            // This should not happen and is likely due to NPM API being broken again
                            // and not property paginating.
                            final String error = "NPM Advisories API is not paginating properly. Aborting mirroring to prevent possible infinite loop. Please open an issue with NPM to resolve. See: https://github.com/DependencyTrack/dependency-track/issues/811";
                            LOGGER.error(error);
                            Notification.dispatch(new Notification()
                                    .scope(NotificationScope.SYSTEM)
                                    .group(NotificationGroup.DATASOURCE_MIRRORING)
                                    .title(NotificationConstants.Title.NPM_ADVISORY_MIRROR)
                                    .content(error)
                                    .level(NotificationLevel.ERROR)
                            );
                            return;
                        }
                    }

                    updateDatasource(results);
                    more = results.getNext() != null;
                    // Workaround for breaking changes made to NPM Advisories API documented in:
                    // https://github.com/DependencyTrack/dependency-track/issues/676
                    if (more) {
                        final String queryString = results.getNext().substring(results.getNext().indexOf("?"));
                        url = NPM_BASE_URL + NPM_ADVISORY_START + queryString;
                    }
                    //url = NPM_BASE_URL + results.getNext(); // No longer works
                } else {
                    final String error = "An unexpected response received from NPM while performing mirror. Response: "
                            + jsonResponse.getStatus() + " " + jsonResponse.getStatusText() + " - Aborting";
                    LOGGER.warn(error);
                    Notification.dispatch(new Notification()
                            .scope(NotificationScope.SYSTEM)
                            .group(NotificationGroup.DATASOURCE_MIRRORING)
                            .title(NotificationConstants.Title.NPM_ADVISORY_MIRROR)
                            .content(error)
                            .level(NotificationLevel.ERROR)
                    );
                    return;
                }
            }
        } catch (UnirestException e) {
            LOGGER.error("An error occurred while retrieving NPM advisory", e);
            successful = false;
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.DATASOURCE_MIRRORING)
                    .title(NotificationConstants.Title.NPM_ADVISORY_MIRROR)
                    .content("An error occurred while retrieving NPM advisory. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Synchronizes the advisories that were downloaded with the internal Dependency-Track database.
     * @param results the results to synchronize
     */
    private void updateDatasource(final AdvisoryResults results) {
        LOGGER.info("Updating datasource with NPM advisories");
        try (QueryManager qm = new QueryManager()) {
            for (final Advisory advisory: results.getAdvisories()) {
                LOGGER.debug("Synchronizing advisory: " + advisory.getId());
                qm.synchronizeVulnerability(mapAdvisoryToVulnerability(qm, advisory), false);
            }
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    /**
     * Helper method that maps an NPM advisory object to a Dependency-Track vulnerability object.
     * @param advisory the NPM advisory to map
     * @return a Dependency-Track Vulnerability object
     */
    private Vulnerability mapAdvisoryToVulnerability(final QueryManager qm, final Advisory advisory) {
        final Vulnerability vuln = new Vulnerability();
        vuln.setSource(Vulnerability.Source.NPM);
        vuln.setVulnId(String.valueOf(advisory.getId()));
        vuln.setDescription(advisory.getOverview());
        vuln.setTitle(advisory.getTitle());
        vuln.setSubTitle(advisory.getModuleName());

        if (StringUtils.isNotBlank(advisory.getCreated())) {
            // final OffsetDateTime odt = OffsetDateTime.parse(advisory.getCreated());
            // vuln.setCreated(Date.from(odt.toInstant()));
            // vuln.setPublished(Date.from(odt.toInstant())); // Advisory does not have published, use created instead.

            // NPM introduced breaking API changes and no longer support ISO 8601 dates with offsets as documented in:
            // https://github.com/DependencyTrack/dependency-track/issues/676
            final Date date = DateUtil.fromISO8601(advisory.getCreated());
            vuln.setCreated(date);
            vuln.setPublished(date); // Advisory does not have published, use created instead.
        }
        if (StringUtils.isNotBlank(advisory.getUpdated())) {
            // final OffsetDateTime odt = OffsetDateTime.parse(advisory.getUpdated());
            // vuln.setUpdated(Date.from(odt.toInstant()));

            // NPM introduced breaking API changes and no longer support ISO 8601 dates with offsets as documented in:
            // https://github.com/DependencyTrack/dependency-track/issues/676
            final Date date = DateUtil.fromISO8601(advisory.getUpdated());
            vuln.setUpdated(date);
        }

        vuln.setCredits(advisory.getFoundBy());
        vuln.setRecommendation(advisory.getRecommendation());
        vuln.setReferences(advisory.getReferences());
        vuln.setVulnerableVersions(advisory.getVulnerableVersions());
        vuln.setPatchedVersions(advisory.getPatchedVersions());

        if (advisory.getCwe() != null) {
            final CweResolver cweResolver = new CweResolver(qm);
            final Cwe cwe = cweResolver.resolve(advisory.getCwe());
            vuln.setCwe(cwe);
        }

        if (advisory.getSeverity() != null) {
            if (advisory.getSeverity().equalsIgnoreCase("Critical")) {
                vuln.setSeverity(Severity.CRITICAL);
            } else if (advisory.getSeverity().equalsIgnoreCase("High")) {
                vuln.setSeverity(Severity.HIGH);
            } else if (advisory.getSeverity().equalsIgnoreCase("Moderate")) {
                vuln.setSeverity(Severity.MEDIUM);
            } else if (advisory.getSeverity().equalsIgnoreCase("Low")) {
                vuln.setSeverity(Severity.LOW);
            } else {
                vuln.setSeverity(Severity.UNASSIGNED);
            }
        } else {
            vuln.setSeverity(Severity.UNASSIGNED);
        }

        return vuln;
    }

}
