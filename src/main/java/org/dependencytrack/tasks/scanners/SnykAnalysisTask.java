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

import static io.github.resilience4j.core.IntervalFunction.ofExponentialBackoff;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.SnykAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.snyk.SnykParser;
import org.dependencytrack.parser.snyk.model.SnykError;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import org.dependencytrack.util.RoundRobinAccessor;
import org.json.JSONArray;
import org.json.JSONObject;
import com.github.packageurl.PackageURL;
import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import alpine.common.util.UrlUtil;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableUncaughtExceptionHandler;
import alpine.event.framework.Subscriber;
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.security.crypto.DataEncryption;
import io.github.resilience4j.micrometer.tagged.TaggedRetryMetrics;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;

/**
 * Subscriber task that performs an analysis of component using Snyk vulnerability REST API.
 *
 * @since 4.7.0
 */
public class SnykAnalysisTask extends BaseComponentAnalyzerTask implements CacheableScanTask, Subscriber {

    private static final Logger LOGGER = Logger.getLogger(SnykAnalysisTask.class);
    private static final Set<String> SUPPORTED_PURL_TYPES = Set.of(
            PackageURL.StandardTypes.CARGO,
            "cocoapods", // Not defined in StandardTypes
            PackageURL.StandardTypes.COMPOSER,
            PackageURL.StandardTypes.GEM,
            PackageURL.StandardTypes.GENERIC,
            PackageURL.StandardTypes.HEX,
            PackageURL.StandardTypes.MAVEN,
            PackageURL.StandardTypes.NPM,
            PackageURL.StandardTypes.NUGET,
            PackageURL.StandardTypes.PYPI
    );
    private static final Retry RETRY;
    private static final ExecutorService EXECUTOR;

    static {
        final RetryRegistry retryRegistry = RetryRegistry.of(RetryConfig.<CloseableHttpResponse>custom()
                .intervalFunction(ofExponentialBackoff(
                        Duration.ofSeconds(Config.getInstance().getPropertyAsInt(ConfigKey.SNYK_RETRY_EXPONENTIAL_BACKOFF_INITIAL_DURATION_SECONDS)),
                        Config.getInstance().getPropertyAsInt(ConfigKey.SNYK_RETRY_EXPONENTIAL_BACKOFF_MULTIPLIER),
                        Duration.ofSeconds(Config.getInstance().getPropertyAsInt(ConfigKey.SNYK_RETRY_EXPONENTIAL_BACKOFF_MAX_DURATION_SECONDS))
                ))
                .maxAttempts(Config.getInstance().getPropertyAsInt(ConfigKey.SNYK_RETRY_MAX_ATTEMPTS))
                .retryOnException(exception -> false)
                .retryOnResult(response -> 429 == response.getStatusLine().getStatusCode())
                .build());
        RETRY = retryRegistry.retry("snyk-api");
        RETRY.getEventPublisher()
                .onRetry(event -> LOGGER.debug("Will execute retry #%d in %s" .formatted(event.getNumberOfRetryAttempts(), event.getWaitInterval())))
                .onError(event -> LOGGER.error("Retry failed after %d attempts: %s" .formatted(event.getNumberOfRetryAttempts(), event.getLastThrowable())));
        TaggedRetryMetrics.ofRetryRegistry(retryRegistry)
                .bindTo(Metrics.getRegistry());

        // The number of threads to be used for Snyk analyzer are configurable.
        // Default is 10. Can be set based on user requirements.
        final int threadPoolSize = Config.getInstance().getPropertyAsInt(ConfigKey.SNYK_THREAD_POOL_SIZE);
        final var threadFactory = new BasicThreadFactory.Builder()
                .namingPattern(SnykAnalysisTask.class.getSimpleName() + "-%d")
                .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                .build();
        EXECUTOR = Executors.newFixedThreadPool(threadPoolSize, threadFactory);
        Metrics.registerExecutorService(EXECUTOR, SnykAnalysisTask.class.getSimpleName());
    }

    private String apiBaseUrl;
    private String apiOrgId;
    private Supplier<String> apiTokenSupplier;
    private String apiVersion;
    private volatile String apiVersionSunset;
    private VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel;

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
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

                if (getApiBaseUrl().isEmpty()) {
                    LOGGER.warn("No API base URL provided; Skipping");
                    return;
                }
                if (orgIdProperty == null || orgIdProperty.getPropertyValue() == null) {
                    LOGGER.warn("No API organization ID provided; Skipping");
                    return;
                }
                if (apiTokenProperty == null || apiTokenProperty.getPropertyValue() == null) {
                    LOGGER.warn("No API token provided; Skipping");
                    return;
                }
                if (apiVersionProperty == null || apiVersionProperty.getPropertyValue() == null) {
                    LOGGER.warn("No API version provided; Skipping");
                    return;
                }

                apiBaseUrl = getApiBaseUrl().get();
                apiOrgId = orgIdProperty.getPropertyValue();
                apiVersion = apiVersionProperty.getPropertyValue();

                try {
                    final String decryptedToken = DataEncryption.decryptAsString(apiTokenProperty.getPropertyValue());
                    apiTokenSupplier = createTokenSupplier(decryptedToken);
                } catch (Exception ex) {
                    LOGGER.error("An error occurred decrypting the Snyk API Token; Skipping", ex);
                    return;
                }
            }
            vulnerabilityAnalysisLevel = event.getVulnerabilityAnalysisLevel();
            LOGGER.info("Starting Snyk vulnerability analysis task");
            if (!event.getComponents().isEmpty()) {
                analyze(event.getComponents());
            }
            LOGGER.info("Snyk vulnerability analysis complete");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.SNYK_ANALYZER;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isCapable(final Component component) {
        final boolean hasValidPurl = component.getPurl() != null
                && component.getPurl().getScheme() != null
                && component.getPurl().getType() != null
                && component.getPurl().getName() != null
                && component.getPurl().getVersion() != null;

        return hasValidPurl && SUPPORTED_PURL_TYPES.stream()
                .anyMatch(purlType -> purlType.equals(component.getPurl().getType()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void analyze(final List<Component> components) {
        final var countDownLatch = new CountDownLatch(components.size());
        for (final Component component : components) {
            if (isCacheCurrent(Vulnerability.Source.SNYK, apiBaseUrl, component.getPurl().getCoordinates())) {
                applyAnalysisFromCache(component);
                countDownLatch.countDown();
                continue;
            }

            CompletableFuture
                    .runAsync(() -> analyzeComponent(component), EXECUTOR)
                    .whenComplete((result, exception) -> {
                        countDownLatch.countDown();

                        if (exception != null) {
                            LOGGER.error("An unexpected error occurred while analyzing %s" .formatted(component), exception);
                        }
                    });
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

        if (apiVersionSunset != null) {
            final var message = """
                    Snyk is indicating that the API version %s has been deprecated and will no longer \
                    be supported as of %s. Please migrate to a newer version of the Snyk API. \
                    Refer to https://apidocs.snyk.io for supported versions.
                    """.formatted(apiVersion, apiVersionSunset);
            LOGGER.warn(message);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .level(NotificationLevel.WARNING)
                    .group(NotificationGroup.ANALYZER)
                    .title("Snyk API version %s is deprecated" .formatted(apiVersion))
                    .content(message));
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean shouldAnalyze(final PackageURL packageUrl) {
        return getApiBaseUrl()
                .map(baseUrl -> !isCacheCurrent(Vulnerability.Source.SNYK, apiBaseUrl, packageUrl.getCoordinates()))
                .orElse(false);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void applyAnalysisFromCache(final Component component) {
        getApiBaseUrl().ifPresent(baseUrl ->
                applyAnalysisFromCache(Vulnerability.Source.SNYK, apiBaseUrl,
                        component.getPurl().getCoordinates(), component, getAnalyzerIdentity(), vulnerabilityAnalysisLevel));
    }

    private void analyzeComponent(final Component component) {
        final String encodedPurl = URLEncoder.encode(component.getPurl().getCoordinates(), StandardCharsets.UTF_8);
        final String requestUrl = "%s/rest/orgs/%s/packages/%s/issues?version=%s" .formatted(apiBaseUrl, apiOrgId, encodedPurl, apiVersion);
        try {
            URIBuilder uriBuilder = new URIBuilder(requestUrl);
            final HttpUriRequest request = new HttpGet(uriBuilder.build().toString());
            request.setHeader(HttpHeaders.USER_AGENT, ManagedHttpClientFactory.getUserAgent());
            request.setHeader(HttpHeaders.AUTHORIZATION, "token " + apiTokenSupplier.get());
            request.setHeader(HttpHeaders.ACCEPT, "application/vnd.api+json");
            try (final CloseableHttpResponse response = RETRY.executeCheckedSupplier(() -> HttpClientPool.getClient().execute(request))) {
                Header header = response.getFirstHeader("Sunset");
                if (header != null) {
                    apiVersionSunset = StringUtils.trimToNull(header.getValue());
                } else {
                    apiVersionSunset = null;
                }
                if (response.getStatusLine().getStatusCode() >= HttpStatus.SC_OK && response.getStatusLine().getStatusCode() < HttpStatus.SC_MULTIPLE_CHOICES) {
                    String responseString = EntityUtils.toString(response.getEntity());
                    JSONObject responseJson = new JSONObject(responseString);
                    handle(component, responseJson);
                } else if (response.getEntity() != null) {
                    String responseString = EntityUtils.toString(response.getEntity());
                    JSONObject responseJson = new JSONObject(responseString);
                    final List<SnykError> errors = new SnykParser().parseErrors(responseJson);
                    if (!errors.isEmpty()) {
                        LOGGER.error("Analysis of component %s failed with HTTP status %d: \n%s"
                                .formatted(component.getPurl(), response.getStatusLine().getStatusCode(), errors.stream()
                                        .map(error -> " - %s: %s (%s)" .formatted(error.title(), error.detail(), error.code()))
                                        .collect(Collectors.joining("\n"))));
                    } else {
                        handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
                    }
                } else {
                    handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
                }
            }
        } catch (Throwable  ex) {
            handleRequestException(LOGGER, ex);
        }
    }

    private void handle(final Component component, final JSONObject object) {
        try (QueryManager qm = new QueryManager()) {
            String purl = null;
            final JSONObject metaInfo = object.optJSONObject("meta");
            if (metaInfo != null) {
                purl = metaInfo.optJSONObject("package").optString("url");
                if (purl == null) {
                    purl = component.getPurlCoordinates().toString();
                }
            }
            final JSONArray data = object.optJSONArray("data");
            if (data != null && !data.isEmpty()) {
                final var snykParser = new SnykParser();
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
            } else {
                addNoVulnerabilityToCache(component);
            }
            updateAnalysisCacheStats(qm, Vulnerability.Source.SNYK, apiBaseUrl, component.getPurl().getCoordinates(), component.getCacheResult());
        }
    }

    private Optional<String> getApiBaseUrl() {
        if (apiBaseUrl != null) {
            return Optional.of(apiBaseUrl);
        }

        try (final var qm = new QueryManager()) {
            final ConfigProperty property = qm.getConfigProperty(
                    ConfigPropertyConstants.SCANNER_SNYK_BASE_URL.getGroupName(),
                    ConfigPropertyConstants.SCANNER_SNYK_BASE_URL.getPropertyName()
            );
            if (property == null) {
                return Optional.empty();
            }

            apiBaseUrl = UrlUtil.normalize(property.getPropertyValue());
            return Optional.of(apiBaseUrl);
        }
    }

    private Supplier<String> createTokenSupplier(final String tokenValue) {
        final String[] tokens = tokenValue.split(";");
        if (tokens.length > 1) {
            LOGGER.debug("Will use %d tokens in round robin" .formatted(tokens.length));
            final var roundRobinAccessor = new RoundRobinAccessor<>(List.of(tokens));
            return roundRobinAccessor::get;
        }

        return apiTokenSupplier = () -> tokenValue;
    }

}
