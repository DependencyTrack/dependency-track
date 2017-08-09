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
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHost;
import org.owasp.dependencytrack.event.NspMirrorEvent;
import org.owasp.dependencytrack.parser.nsp.NspAdvsoriesParser;
import org.owasp.dependencytrack.parser.nsp.model.AdvisoryResults;
import java.util.Date;

public class NspMirrorTask implements Subscriber {

    private static final String NSP_API_BASE_URL = "https://api.nodesecurity.io/advisories";
    private static final Logger LOGGER = Logger.getLogger(NspMirrorTask.class);

    public void inform(Event e) {
        if (e instanceof NspMirrorEvent) {
            LOGGER.info("Starting NSP mirroring task");
            getAdvisories();
            LOGGER.info("NSP mirroring complete");
        }
    }

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

    private void updateDatasource(AdvisoryResults results) {
        LOGGER.info("Updating datasource with NSP advisories");
        // todo: sync advisories with database
    }

}
