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
import org.dependencytrack.event.NspMirrorEvent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.nsp.NspAdvsoriesParser;
import org.dependencytrack.parser.nsp.model.Advisory;
import org.dependencytrack.parser.nsp.model.AdvisoryResults;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.HttpClientFactory;
import us.springett.cvss.Cvss;
import us.springett.cvss.CvssV2;
import us.springett.cvss.CvssV3;
import us.springett.cvss.Score;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.Date;

/**
 * Subscriber task that performs a mirror of the Node Security Platform public advisories.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class NspMirrorTask implements LoggableSubscriber {

    private static final String NSP_API_BASE_URL = "https://api.nodesecurity.io/advisories";
    private static final Logger LOGGER = Logger.getLogger(NspMirrorTask.class);

    private boolean successful = true;

    /**
     * {@inheritDoc}
     */
    public void inform(Event e) {
        if (e instanceof NspMirrorEvent) {
            LOGGER.info("Starting NSP mirroring task");
            getAdvisories();
            LOGGER.info("NSP mirroring complete");
            if (successful) {
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.DATASOURCE_MIRRORING)
                        .title(NotificationConstants.Title.NSP_MIRROR)
                        .content("Mirroring of the Node Security Platform completed successfully")
                        .level(NotificationLevel.INFORMATIONAL)
                );
            }
        }
    }

    /**
     * Performs an incremental mirror (using pagination) of the NSP public advisory database.
     */
    private void getAdvisories() {
        final Date currentDate = new Date();
        LOGGER.info("Retrieving NSP advisories at " + currentDate);

        try {
            Unirest.setHttpClient(HttpClientFactory.createClient());

            boolean more = true;
            int offset = 0;
            while (more) {
                LOGGER.info("Retrieving NSP advisories from " + NSP_API_BASE_URL);
                final HttpResponse<JsonNode> jsonResponse = Unirest.get(NSP_API_BASE_URL)
                        .header("accept", "application/json")
                        .queryString("offset", offset)
                        .asJson();

                if (jsonResponse.getStatus() == 200) {
                    final NspAdvsoriesParser parser = new NspAdvsoriesParser();
                    final AdvisoryResults results = parser.parse(jsonResponse.getBody());
                    updateDatasource(results);
                    more = results.getCount() + results.getOffset() != results.getTotal();
                    offset += results.getCount();
                }
            }
        } catch (UnirestException e) {
            LOGGER.error("An error occurred while retrieving NSP advisory", e);
            successful = false;
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.DATASOURCE_MIRRORING)
                    .title(NotificationConstants.Title.NSP_MIRROR)
                    .content("An error occurred while retrieving NSP advisory. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Synchronizes the advisories that were downloaded with the internal Dependency-Track database.
     * @param results the results to synchronize
     */
    private void updateDatasource(AdvisoryResults results) {
        LOGGER.info("Updating datasource with NSP advisories");
        try (QueryManager qm = new QueryManager()) {
            for (Advisory advisory: results.getAdvisories()) {
                qm.synchronizeVulnerability(mapAdvisoryToVulnerability(advisory), false);
            }
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    /**
     * Helper method that maps an NSP advisory object to a Dependency-Track vulnerability object.
     * @param advisory the NSP advisory to map
     * @return a Dependency-Track Vulnerability object
     */
    private Vulnerability mapAdvisoryToVulnerability(Advisory advisory) {
        final Vulnerability vuln = new Vulnerability();
        vuln.setSource(Vulnerability.Source.NSP);
        vuln.setVulnId(String.valueOf(advisory.getId()));
        vuln.setDescription(advisory.getOverview());
        vuln.setTitle(advisory.getTitle());
        vuln.setSubTitle(advisory.getModuleName());

        if (StringUtils.isNotBlank(advisory.getCreatedAt())) {
            final OffsetDateTime odt = OffsetDateTime.parse(advisory.getCreatedAt());
            vuln.setCreated(Date.from(odt.toInstant()));
        }
        if (StringUtils.isNotBlank(advisory.getPublishDate())) {
            final OffsetDateTime odt = OffsetDateTime.parse(advisory.getPublishDate());
            vuln.setPublished(Date.from(odt.toInstant()));
        }
        if (StringUtils.isNotBlank(advisory.getUpdatedAt())) {
            final OffsetDateTime odt = OffsetDateTime.parse(advisory.getUpdatedAt());
            vuln.setUpdated(Date.from(odt.toInstant()));
        }

        final Cvss cvss = Cvss.fromVector(advisory.getCvssVector());
        if (cvss != null) {
            final Score score = cvss.calculateScore();
            if (cvss instanceof CvssV2) {
                vuln.setCvssV2Vector(cvss.getVector());
                vuln.setCvssV2BaseScore(BigDecimal.valueOf(score.getBaseScore()));
                vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
                vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
            } else if (cvss instanceof CvssV3) {
                vuln.setCvssV3Vector(cvss.getVector());
                vuln.setCvssV3BaseScore(BigDecimal.valueOf(score.getBaseScore()));
                vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
                vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
            }
        }

        vuln.setCredits(advisory.getAuthor());
        vuln.setRecommendation(advisory.getRecommendation());
        vuln.setReferences(advisory.getReferences());
        vuln.setVulnerableVersions(advisory.getVulnerableVersions());
        vuln.setPatchedVersions(advisory.getPatchedVersions());

        return vuln;
    }

}
