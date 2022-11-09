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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableUncaughtExceptionHandler;
import alpine.event.framework.Subscriber;
import alpine.model.ConfigProperty;
import alpine.security.crypto.DataEncryption;
import com.github.packageurl.PackageURL;
import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterConfig;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;
import kong.unirest.GetRequest;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.UnirestException;
import kong.unirest.UnirestInstance;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.apache.http.HttpHeaders;
import org.dependencytrack.common.ConfigKey;
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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_BASE_URL;

/**
 * Subscriber task that performs an analysis of component using Snyk vulnerability REST API.
 *
 * @since 4.7.0
 */
public class SnykAnalysisTask extends BaseComponentAnalyzerTask implements CacheableScanTask, Subscriber {

    private static final Logger LOGGER = Logger.getLogger(SnykAnalysisTask.class);

    private static final RateLimiterConfig config = RateLimiterConfig.custom()
            .limitForPeriod(Config.getInstance().getPropertyAsInt(ConfigKey.SNYK_LIMIT_FOR_PERIOD))
            .timeoutDuration(Duration.ofSeconds(Config.getInstance().getPropertyAsInt(ConfigKey.SNYK_THREAD_TIMEOUT_DURATION)))
            .limitRefreshPeriod(Duration.ofSeconds(Config.getInstance().getPropertyAsInt(ConfigKey.SNYK_LIMIT_REFRESH_PERIOD)))
            .build();
    RateLimiterRegistry registry = RateLimiterRegistry.of(config);
    RateLimiter limiter = registry.rateLimiter("SnykAnalysis");
    private static final ExecutorService EXECUTOR;

    static {
        // The number of threads to be used for Snyk analyzer are configurable.
        // Default is 10. Can be set based on user requirements.
        final int threadPoolSize = Config.getInstance().getPropertyAsInt(ConfigKey.SNYK_THREAD_BATCH_SIZE);
        final var threadFactory = new BasicThreadFactory.Builder()
                .namingPattern(SnykAnalysisTask.class.getSimpleName() + "-%d")
                .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                .build();
        EXECUTOR = Executors.newFixedThreadPool(threadPoolSize, threadFactory);
        Metrics.registerExecutorService(EXECUTOR, SnykAnalysisTask.class.getSimpleName());
    }

    private String apiBaseUrl;
    private String apiEndPoint = "/issues?";
    private String apiToken;
    private Long duration = 0L;
    private VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel;

    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.SNYK_ANALYZER;
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        Instant start = Instant.now();
        if (e instanceof final SnykAnalysisEvent event) {
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
                    String orgId = orgIdProperty.getPropertyValue();
                    apiBaseUrl = baseUrl + "/rest/orgs/" + orgId + "/packages/";
                } catch (Exception ex) {
                    LOGGER.error("An error occurred decrypting the Snyk API Token. Skipping", ex);
                    return;
                }
            }
            vulnerabilityAnalysisLevel = event.getVulnerabilityAnalysisLevel();
            LOGGER.info("Starting Snyk vulnerability analysis task");
            if (!event.getComponents().isEmpty()) {
                analyze(event.getComponents());
            }
            Instant end = Instant.now();
            LOGGER.info("Snyk vulnerability analysis complete");
            long timeElapsed = Duration.between(start, end).toMillis();
            timeElapsed += duration;
            LOGGER.info("Time taken to complete snyk vulnerability analysis task: " + timeElapsed + " milliseconds");
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
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        CountDownLatch countDownLatch = new CountDownLatch(components.size());
        for (final Component component : components) {
            Runnable analysisUtil = () -> {
                try {
                    final String snykUrl = apiBaseUrl + URLEncoder.encode(component.getPurlCoordinates().toString(), StandardCharsets.UTF_8) + apiEndPoint;
                    try {
                        final GetRequest request = ui.get(snykUrl)
                                .header(HttpHeaders.AUTHORIZATION, this.apiToken);
                        final HttpResponse<JsonNode> jsonResponse = request.asJson();
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
                } finally {
                    countDownLatch.countDown();
                }
            };
            analysisUtil = RateLimiter.decorateRunnable(limiter, analysisUtil);
            Instant startThread = Instant.now();
            if (!isCacheCurrent(Vulnerability.Source.SNYK, apiBaseUrl, component.getPurl().toString())) {
                EXECUTOR.execute(analysisUtil);
            } else {
                applyAnalysisFromCache(Vulnerability.Source.SNYK, apiBaseUrl, component.getPurl().toString(), component, getAnalyzerIdentity(), vulnerabilityAnalysisLevel);
            }
            Instant endThread = Instant.now();
            duration += Duration.between(startThread, endThread).toMillis();
        }
        try {
            if (!countDownLatch.await(60, TimeUnit.MINUTES)) {
                // Depending on the system load, it may take a while for the queued events
                // to be processed. And depending on how large the projects are, it may take a
                // while for the processing of the respective event to complete.
                // It is unlikely though that either of these situations causes a block for
                // over 60 minutes. If that happens, the system is under-resourced.
                LOGGER.debug("The Analysis for project :" + components.get(0).getProject().getName() + "took longer than expected");
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

    @Override
    public boolean shouldAnalyze(PackageURL packageUrl) {
        return !isCacheCurrent(Vulnerability.Source.SNYK, apiBaseUrl, packageUrl.toString());
    }

    @Override
    public void applyAnalysisFromCache(Component component) {
        applyAnalysisFromCache(Vulnerability.Source.SNYK, apiBaseUrl, component.getPurl().toString(), component, getAnalyzerIdentity(), vulnerabilityAnalysisLevel);
    }
}
