/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.tasks;

import alpine.Config;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.event.framework.SingleThreadedEventService;
import alpine.logging.Logger;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHost;
import org.owasp.dependencytrack.event.IndexEvent;
import org.owasp.dependencytrack.event.NspMirrorEvent;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.parser.nsp.NspAdvsoriesParser;
import org.owasp.dependencytrack.parser.nsp.model.Advisory;
import org.owasp.dependencytrack.parser.nsp.model.AdvisoryResults;
import org.owasp.dependencytrack.persistence.QueryManager;
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

    /**
     * {@inheritDoc}
     */
    public void inform(Event e) {
        if (e instanceof NspMirrorEvent) {
            LOGGER.info("Starting NSP mirroring task");
            getAdvisories();
            LOGGER.info("NSP mirroring complete");
        }
    }

    /**
     * Performs an incremental mirror (using pagination) of the NSP public advisory database.
     */
    private void getAdvisories() {
        final Date currentDate = new Date();
        LOGGER.info("Retrieving NSP advisories at " + currentDate);

        try {
            final String proxyAddr = Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_ADDRESS);
            if (StringUtils.isNotBlank(proxyAddr)) {
                final Integer proxyPort = Config.getInstance().getPropertyAsInt(Config.AlpineKey.HTTP_PROXY_PORT);
                Unirest.setProxy(new HttpHost(proxyAddr, proxyPort));
            }

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
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
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
