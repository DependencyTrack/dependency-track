/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import io.github.openunirest.http.HttpResponse;
import io.github.openunirest.http.JsonNode;
import io.github.openunirest.http.Unirest;
import io.github.openunirest.http.exceptions.UnirestException;
import org.apache.commons.lang3.StringUtils;
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
import org.dependencytrack.util.HttpClientFactory;
import java.time.OffsetDateTime;
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
    public void inform(Event e) {
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
            Unirest.setHttpClient(HttpClientFactory.createClient());

            boolean more = true;

            String url = NPM_BASE_URL + NPM_ADVISORY_START;
            while (more) {
                LOGGER.info("Retrieving NPM advisories from " + url);
                final HttpResponse<JsonNode> jsonResponse = Unirest.get(url)
                        .header("accept", "application/json")
                        .asJson();

                if (jsonResponse.getStatus() == 200) {
                    final NpmAdvisoriesParser parser = new NpmAdvisoriesParser();
                    final AdvisoryResults results = parser.parse(jsonResponse.getBody());
                    updateDatasource(results);
                    more = results.getNext() != null;
                    url = NPM_BASE_URL + results.getNext();
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
    private void updateDatasource(AdvisoryResults results) {
        LOGGER.info("Updating datasource with NPM advisories");
        try (QueryManager qm = new QueryManager()) {
            for (Advisory advisory: results.getAdvisories()) {
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
    private Vulnerability mapAdvisoryToVulnerability(QueryManager qm, Advisory advisory) {
        final Vulnerability vuln = new Vulnerability();
        vuln.setSource(Vulnerability.Source.NPM);
        vuln.setVulnId(String.valueOf(advisory.getId()));
        vuln.setDescription(advisory.getOverview());
        vuln.setTitle(advisory.getTitle());
        vuln.setSubTitle(advisory.getModuleName());

        if (StringUtils.isNotBlank(advisory.getCreated())) {
            final OffsetDateTime odt = OffsetDateTime.parse(advisory.getCreated());
            vuln.setCreated(Date.from(odt.toInstant()));
            vuln.setPublished(Date.from(odt.toInstant())); // Advisory does not have published, use created instead.
        }
        if (StringUtils.isNotBlank(advisory.getUpdated())) {
            final OffsetDateTime odt = OffsetDateTime.parse(advisory.getUpdated());
            vuln.setUpdated(Date.from(odt.toInstant()));
        }

        vuln.setCredits(advisory.getFoundBy());
        vuln.setRecommendation(advisory.getRecommendation());
        vuln.setReferences(advisory.getReferences());
        vuln.setVulnerableVersions(advisory.getVulnerableVersions());
        vuln.setPatchedVersions(advisory.getPatchedVersions());

        if (advisory.getCwe() != null) {
            CweResolver cweResolver = new CweResolver(qm);
            Cwe cwe = cweResolver.resolve(advisory.getCwe());
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
