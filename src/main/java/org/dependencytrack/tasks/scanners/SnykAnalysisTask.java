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
package org.dependencytrack.tasks.scanners;

import alpine.common.logging.Logger;
import alpine.Config;
import kong.unirest.*;
import org.dependencytrack.common.ConfigKey;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.model.ConfigProperty;
import alpine.security.crypto.DataEncryption;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHeaders;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.SnykAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.parser.snyk.SnykParser;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_BASE_URL;

/**
 * Subscriber task that performs an analysis of component using Snyk vulnerability REST API.
 */
public class SnykAnalysisTask extends BaseComponentAnalyzerTask implements Subscriber {

    private String apiBaseUrl;
    private static String apiEndPoint = "/issues?";

    //number of threads to be used for snyk analyzer are configurable. Default is 10. Can be set based on user requirements.
    private static final ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Config.getInstance().getPropertyAsInt(ConfigKey.SNYK_THREAD_BATCH_SIZE));
    private static final Logger LOGGER = Logger.getLogger(SnykAnalysisTask.class);
    private static final RetryConfig RETRY_CONFIG = RetryConfig.custom()
            .retryExceptions(IllegalStateException.class)
            .waitDuration(Duration.ofSeconds(Config.getInstance().getPropertyAsInt(ConfigKey.SNYK_WAIT_BETWEEN_RETRIES)))
            .maxAttempts(Config.getInstance().getPropertyAsInt(ConfigKey.SNYK_MAX_RETRIES))
            .build();
    private String apiToken;
    private static int duration = 0;
    private VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel;

    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.SNYK_ANALYZER;
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        Instant start = Instant.now();
        if (e instanceof SnykAnalysisEvent) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_SNYK_ENABLED)) {
                return;
            }
            try (QueryManager qm = new QueryManager()) {
                final ConfigProperty apiTokenProperty = qm.getConfigProperty(
                        ConfigPropertyConstants.SCANNER_SNYK_API_TOKEN.getGroupName(),
                        ConfigPropertyConstants.SCANNER_SNYK_API_TOKEN.getPropertyName()
                );
                final ConfigProperty orgIdProperty = qm.getConfigProperty(
                        ConfigPropertyConstants.SCANNER_SNYK_ORG_ID.getGroupName(),
                        ConfigPropertyConstants.SCANNER_SNYK_ORG_ID.getPropertyName()
                );
                final ConfigProperty apiVersionProperty = qm.getConfigProperty(
                        ConfigPropertyConstants.SCANNER_SNYK_API_VERSION.getGroupName(),
                        ConfigPropertyConstants.SCANNER_SNYK_API_VERSION.getPropertyName()
                );
                if (apiTokenProperty == null || apiTokenProperty.getPropertyValue() == null) {
                    LOGGER.error("Please provide API token for use with Snyk");
                    return;
                }
                if (orgIdProperty == null || orgIdProperty.getPropertyValue() == null) {
                    LOGGER.error("Please provide organization ID to access Snyk");
                    return;
                }
                if (apiVersionProperty == null || apiVersionProperty.getPropertyValue() == null) {
                    LOGGER.error("Please provide Snyk API version");
                    return;
                }
                String baseUrl = qm.getConfigProperty(
                        SCANNER_SNYK_BASE_URL.getGroupName(),
                        SCANNER_SNYK_BASE_URL.getPropertyName()).getPropertyValue();
                if (baseUrl != null && baseUrl.endsWith("/")) {
                    baseUrl = StringUtils.chop(baseUrl);
                }
                try {
                    apiToken = "token " + DataEncryption.decryptAsString(apiTokenProperty.getPropertyValue());
                    apiEndPoint += "version=" + apiVersionProperty.getPropertyValue().trim();
                    String ORG_ID = orgIdProperty.getPropertyValue();
                    apiBaseUrl = baseUrl + "/rest/orgs/" + ORG_ID + "/packages/";
                } catch (Exception ex) {
                    LOGGER.error("An error occurred decrypting the Snyk API Token. Skipping", ex);
                    return;
                }
            }
            final SnykAnalysisEvent event = (SnykAnalysisEvent) e;
            vulnerabilityAnalysisLevel = event.getVulnerabilityAnalysisLevel();
            LOGGER.info("Starting Snyk vulnerability analysis task");
            if (!event.getComponents().isEmpty()) {
                analyze(event.getComponents());
            }
            Instant end = Instant.now();
            LOGGER.info("Snyk vulnerability analysis complete");
            Duration timeElapsed = Duration.between(start, end);
            LOGGER.info("Time taken to complete snyk vulnerability analysis task: " + timeElapsed.toMillis() + duration + " milliseconds");
        }
    }

    /**
     * Determines if the {@link SnykAnalysisTask} is capable of analyzing the specified Component.
     *
     * @param component the Component to analyze
     * @return true if SnykAnalysisTask should analyze, false if not
     */
    public boolean isCapable(final Component component) {
        return component.getPurl() != null
                && component.getPurl().getScheme() != null
                && component.getPurl().getType() != null
                && component.getPurl().getName() != null
                && component.getPurl().getVersion() != null;
    }

    /**
     * Analyzes a list of Components.
     *
     * @param components a list of Components
     */
    public void analyze(final List<Component> components) {
        int trackComponent = 0;
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        CountDownLatch countDownLatch = new CountDownLatch(components.size());
        for (final Component component : components) {
            if (trackComponent < components.size()) {
                trackComponent += 1;
                Runnable analysisUtil = () -> {
                    try {
                        final String snykUrl = apiBaseUrl + URLEncoder.encode(component.getPurlCoordinates().toString(), StandardCharsets.UTF_8) + apiEndPoint;
                        if (!isCacheCurrent(Vulnerability.Source.SNYK, apiBaseUrl, component.getPurl().toString())) {
                            try {
                                final GetRequest request = ui.get(snykUrl)
                                        .header(HttpHeaders.AUTHORIZATION, this.apiToken);
                                final HttpResponse<JsonNode> jsonResponse = Retry.of("getSnykResponse", RETRY_CONFIG).executeSupplier(() -> {
                                    final HttpResponse<JsonNode> response = request.asJson();
                                    if (HttpStatus.TOO_MANY_REQUESTS == response.getStatus()
                                            || HttpStatus.SERVICE_UNAVAILABLE == response.getStatus()) {
                                        LOGGER.warn("Received status "+response.getStatus()+".");
                                        throw new IllegalStateException();
                                    }
                                    return response;
                                });
                                if (jsonResponse.getStatus() == 200 || jsonResponse.getStatus() == 404) {
                                    if (jsonResponse.getStatus() == 200) {
                                        handle(component, jsonResponse.getBody().getObject(), jsonResponse.getStatus());
                                    } else if (jsonResponse.getStatus() == 404) {
                                        handle(component, null, jsonResponse.getStatus());
                                    }
                                } else {
                                    handleUnexpectedHttpResponse(LOGGER, apiBaseUrl, jsonResponse.getStatus(), jsonResponse.getStatusText());
                                }
                            } catch (UnirestException e) {
                                handleRequestException(LOGGER, e);
                            }
                        } else {
                            LOGGER.debug("Cache is current, apply snyk analysis from cache");
                            applyAnalysisFromCache(Vulnerability.Source.SNYK, apiBaseUrl, component.getPurl().toString(), component, getAnalyzerIdentity(), vulnerabilityAnalysisLevel);
                        }
                    } finally {
                        countDownLatch.countDown();
                    }
                };
                Instant startThread = Instant.now();
                executor.execute(analysisUtil);

                Instant endThread = Instant.now();
                duration += Duration.between(startThread, endThread).toMillis();
            }
        }
        try {
            if (!countDownLatch.await(60, TimeUnit.MINUTES)) {
                // Depending on the system load, it may take a while for the queued events
                // to be processed. And depending on how large the projects are, it may take a
                // while for the processing of the respective event to complete.
                // It is unlikely though that either of these situations causes a block for
                // over 60 minutes. If that happens, the system is under-resourced.
                LOGGER.warn("The Analysis for project :" + components.get(0).getProject().getName() + "took longer than expected");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }


    public void handle(Component component, JSONObject object, int responseCode) {

        try (QueryManager qm = new QueryManager()) {
            if (responseCode == 200) {
                String purl = null;
                final JSONObject metaInfo = object.optJSONObject("meta");
                if (metaInfo != null) {
                    purl = metaInfo.optJSONObject("package").optString("url");
                    if (purl == null) {
                        purl = component.getPurlCoordinates().toString();
                    }
                }
                final JSONArray data = object.optJSONArray("data");
                if (data != null) {
                    SnykParser snykParser = new SnykParser();
                    for (int count = 0; count < data.length(); count++) {
                        Vulnerability synchronizedVulnerability = snykParser.parse(data, qm, purl, count);
                        addVulnerabilityToCache(component, synchronizedVulnerability);
                        final Component componentPersisted = qm.getObjectByUuid(Component.class, component.getUuid());
                        if (componentPersisted != null && synchronizedVulnerability.getVulnId() != null) {
                            NotificationUtil.analyzeNotificationCriteria(qm, synchronizedVulnerability, componentPersisted, vulnerabilityAnalysisLevel);
                            qm.addVulnerability(synchronizedVulnerability, componentPersisted, this.getAnalyzerIdentity());
                            LOGGER.debug("Snyk vulnerability added : " + synchronizedVulnerability.getVulnId() + " to component " + component.getName());
                        }
                        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
                    }
                }
                if (component.getPurl() != null && apiBaseUrl != null) {
                    updateAnalysisCacheStats(qm, Vulnerability.Source.SNYK, apiBaseUrl, component.getPurl().toString(), component.getCacheResult());
                }
            } else if (responseCode == 404) {
                Vulnerability vulnerability = new Vulnerability();
                addVulnerabilityToCache(component, vulnerability);
                if (component.getPurl() != null && apiBaseUrl != null) {
                    updateAnalysisCacheStats(qm, Vulnerability.Source.SNYK, apiBaseUrl, component.getPurl().toString(), component.getCacheResult());
                }
            }
        }
    }
}
