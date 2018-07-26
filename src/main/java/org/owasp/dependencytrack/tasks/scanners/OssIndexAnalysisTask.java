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
package org.owasp.dependencytrack.tasks.scanners;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import alpine.util.Pageable;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.openunirest.http.HttpResponse;
import io.github.openunirest.http.JsonNode;
import io.github.openunirest.http.Unirest;
import io.github.openunirest.http.exceptions.UnirestException;
import org.json.JSONObject;
import org.owasp.dependencytrack.event.OssIndexAnalysisEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.parser.ossindex.OssIndexParser;
import org.owasp.dependencytrack.parser.ossindex.model.ComponentReport;
import org.owasp.dependencytrack.parser.ossindex.model.ComponentReportVulnerability;
import org.owasp.dependencytrack.persistence.QueryManager;
import org.owasp.dependencytrack.util.HttpClientFactory;
import java.util.ArrayList;
import java.util.List;

/**
 * Subscriber task that performs an analysis of component using Sonatype OSS Index REST API.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
public class OssIndexAnalysisTask extends BaseComponentAnalyzerTask implements Subscriber {

    private static final String API_BASE_URL = "https://ossindex.net/api/v3/component-report";
    private static final Logger LOGGER = Logger.getLogger(OssIndexAnalysisTask.class);

    public OssIndexAnalysisTask() {
        super(100, 5);
    }

    /**
     * {@inheritDoc}
     */
    public void inform(Event e) {
        if (e instanceof OssIndexAnalysisEvent) {
            final OssIndexAnalysisEvent event = (OssIndexAnalysisEvent)e;
            LOGGER.info("Starting Sonatype OSS Index analysis task");
            if (event.getComponents().size() > 0) {
                analyze(event.getComponents());
            } else {
                super.analyze();
            }
            LOGGER.info("Sonatype OSS Index analysis complete");
        }
    }

    /**
     * Determines if the {@link OssIndexAnalysisTask} is suitable for analysis based on the PackageURL.
     *
     * @param purl the PackageURL to analyze
     * @return true if OssIndexAnalysisTask should analyze, false if not
     */
    public boolean shouldAnalyze(PackageURL purl) {
        if (purl == null) {
            return false;
        }
        return true;
    }

    /**
     * Analyzes a list of Components.
     * @param components a list of Components
     */
    public void analyze(List<Component> components) {
        Pageable<Component> paginatedComponents = new Pageable<>(100, components);
        while (!paginatedComponents.isPaginationComplete()) {
            final List<String> coordinates = new ArrayList<>();
            List<Component> paginatedList = paginatedComponents.getPaginatedList();
            for (Component component: paginatedList) {
                if (shouldAnalyze(component.getPurl())) {
                    coordinates.add(component.getPurl().canonicalize());
                }
            }
            if (coordinates.size() == 0) {
                return;
            }
            final JSONObject json = new JSONObject();
            json.put("coordinates", coordinates);
            try {
                final List<ComponentReport> report = submit(json);
                processResults(report, paginatedList);
            } catch (UnirestException e) {
                LOGGER.error("An error occurred while analyzing", e);
            }
            LOGGER.info("Analyzing " + coordinates.size() + " component(s)");
            doThrottleDelay();
            paginatedComponents.nextPage();
        }
    }

    /**
     * Submits the payload to the Sonatype OSS Index service
     */
    private List<ComponentReport> submit(JSONObject payload) throws UnirestException {
        Unirest.setHttpClient(HttpClientFactory.createClient());
        final HttpResponse<JsonNode> jsonResponse = Unirest.post(API_BASE_URL)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("User-Agent", HttpClientFactory.getUserAgent())
                .body(payload)
                .asJson();
        if (jsonResponse.getStatus() == 200) {
            final OssIndexParser parser = new OssIndexParser();
            return parser.parse(jsonResponse.getBody());
        } else {
            LOGGER.warn("Received unexpected HTTP response " + jsonResponse.getStatus() + " " + jsonResponse.getStatusText());
        }
        return new ArrayList<>();
    }

    private void processResults(List<ComponentReport> report, List<Component> componentsScanned) {
        try (QueryManager qm = new QueryManager()) {
            for (ComponentReport componentReport: report) {
                for (Component component: componentsScanned) {
                    final String componentPurl = component.getPurl().canonicalize();
                    final PackageURL sonatypePurl = oldPurlResolver(componentReport.getCoordinates());
                    if (componentPurl.equals(componentReport.getCoordinates()) ||
                            (sonatypePurl != null && componentPurl.equals(sonatypePurl.canonicalize()))) {
                        /*
                        Found the component
                         */
                        for (ComponentReportVulnerability reportedVuln: componentReport.getVulnerabilities()) {
                            /*
                            TODO: Parse reportedVuln, lookup vuln in db, add vuln to component, set source to ODDINDEX
                            TODO: https://github.com/sonatype/ossindex-public/issues/1
                             */
                        }
                    }
                }
            }
        }
    }

    /**
     * Sonatype OSS Index currently uses an old/outdated version of the PackageURL specification.
     * Attempt to convert it into the current spec format and return it.
     */
    private PackageURL oldPurlResolver(String coordinates) {
        try {
            return new PackageURL("pkg:" + coordinates.replaceFirst(":", "/"));
        } catch (MalformedPackageURLException e) {
            return null;
        }
    }
}