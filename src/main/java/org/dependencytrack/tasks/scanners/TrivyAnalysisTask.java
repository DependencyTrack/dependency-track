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
import alpine.common.metrics.Metrics;
import alpine.common.util.UrlUtil;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableUncaughtExceptionHandler;
import alpine.event.framework.Subscriber;
import alpine.model.ConfigProperty;
import alpine.security.crypto.DataEncryption;
import com.github.packageurl.PackageURL;
import com.google.gson.Gson;

import io.github.resilience4j.micrometer.tagged.TaggedRetryMetrics;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.TrivyAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.parser.trivy.TrivyParser;
import org.dependencytrack.parser.trivy.model.Application;
import org.dependencytrack.parser.trivy.model.PutRequest;
import org.dependencytrack.parser.trivy.model.ScanRequest;
import org.dependencytrack.parser.trivy.model.Options;
import org.dependencytrack.parser.trivy.model.DeleteRequest;
import org.dependencytrack.parser.trivy.model.BlobInfo;
import org.dependencytrack.parser.trivy.model.TrivyError;
import org.dependencytrack.parser.trivy.model.TrivyResponse;
import org.dependencytrack.parser.trivy.model.Library;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import org.dependencytrack.util.RoundRobinAccessor;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;


/**
 * Subscriber task that performs an analysis of component using Trivy vulnerability API.
 *
 * @since 4.7.0
 */
public class TrivyAnalysisTask extends BaseComponentAnalyzerTask implements CacheableScanTask, Subscriber {

    private static final Logger LOGGER = Logger.getLogger(TrivyAnalysisTask.class);
    private static final String TOKEN_HEADER = "Trivy-Token";
    private static final Retry RETRY;
    private static final ExecutorService EXECUTOR;

    static {
        final RetryRegistry retryRegistry = RetryRegistry.of(RetryConfig.<CloseableHttpResponse>custom()
                .retryOnException(exception -> false)
                .retryOnResult(response -> 429 == response.getStatusLine().getStatusCode())
                .build());
        RETRY = retryRegistry.retry("trivy-api");
        RETRY.getEventPublisher()
                .onRetry(event -> LOGGER.debug("Will execute retry #%d in %s" .formatted(event.getNumberOfRetryAttempts(), event.getWaitInterval())))
                .onError(event -> LOGGER.error("Retry failed after %d attempts: %s" .formatted(event.getNumberOfRetryAttempts(), event.getLastThrowable())));
        TaggedRetryMetrics.ofRetryRegistry(retryRegistry)
                .bindTo(Metrics.getRegistry());

        // The number of threads to be used for Trivy analyzer are configurable.
        // Default is 10. Can be set based on user requirements.
        final int threadPoolSize = 10;
        final var threadFactory = new BasicThreadFactory.Builder()
                .namingPattern(TrivyAnalysisTask.class.getSimpleName() + "-%d")
                .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                .build();
        EXECUTOR = Executors.newFixedThreadPool(threadPoolSize, threadFactory);
        Metrics.registerExecutorService(EXECUTOR, TrivyAnalysisTask.class.getSimpleName());
    }

    private String apiBaseUrl;
    private Supplier<String> apiTokenSupplier;
    private VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel;

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
        if (e instanceof final TrivyAnalysisEvent event) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_TRIVY_ENABLED)) {
                return;
            }
            try (QueryManager qm = new QueryManager()) {
                final ConfigProperty apiTokenProperty = qm.getConfigProperty(
                        ConfigPropertyConstants.SCANNER_TRIVY_API_TOKEN.getGroupName(),
                        ConfigPropertyConstants.SCANNER_TRIVY_API_TOKEN.getPropertyName()
                );

                if (apiTokenProperty == null || apiTokenProperty.getPropertyValue() == null) {
                    LOGGER.warn("No API token provided; Skipping");
                    return;
                }
                if (getApiBaseUrl().isEmpty()) {
                    LOGGER.warn("No API base URL provided; Skipping");
                    return;
                }

                apiBaseUrl = getApiBaseUrl().get();

                try {
                    final String decryptedToken = DataEncryption.decryptAsString(apiTokenProperty.getPropertyValue());
                    apiTokenSupplier = createTokenSupplier(decryptedToken);
                } catch (Exception ex) {
                    LOGGER.error("An error occurred decrypting the API Token; Skipping", ex);
                    return;
                }
            }
            vulnerabilityAnalysisLevel = event.getVulnerabilityAnalysisLevel();
            LOGGER.info("Starting Trivy vulnerability analysis task");
            if (!event.getComponents().isEmpty()) {
                analyze(event.getComponents());
            }
            LOGGER.info("Trivy vulnerability analysis complete");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.TRIVY_ANALYZER;
    }

    @Override
    public boolean isCapable(Component component) {
        return true;
    }
    /**
     * {@inheritDoc}
     */
    @Override
    public void analyze(final List<Component> components) {
        final var countDownLatch = new CountDownLatch(components.size());

        // if (isCacheCurrent(Vulnerability.Source.TRIVY, apiBaseUrl, component.getPurl().getCoordinates())) {
        //     applyAnalysisFromCache(component);
        //     countDownLatch.countDown();
        //     continue;
        // }

        var info = new BlobInfo();

        var app = new Application("jar");

        for (final Component component : components) {
            LOGGER.debug("-----------------------------");
            LOGGER.debug("CPE: " + component.getCpe());
            LOGGER.debug("CPE: " + component.getPurl());
            LOGGER.debug("Group: " + component.getGroup());
            LOGGER.debug("Name: " + component.getName());
            LOGGER.debug("Version: " + component.getVersion());
            LOGGER.debug("-----------------------------");

            app.addLibrary(new Library(component.getGroup() + ":" + component.getName(), component.getVersion()));
        }

        info.setApplications(new Application[] {app});
        var blob = new PutRequest();
        blob.setBlobInfo(info);
        blob.setDiffID("sha256:82b8626f712f721809b12af37380479b68263b78600dea0b280ee8fc88e3d27a");

        CompletableFuture
                    .runAsync(() -> analyzeBlob(blob), EXECUTOR)
                    .whenComplete((result, exception) -> {
                        countDownLatch.countDown();

                        if (exception != null) {
                            LOGGER.error("An unexpected error occurred while analyzing %s" .formatted("x"), exception);
                        }
                    });

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

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean shouldAnalyze(final PackageURL packageUrl) {
        return getApiBaseUrl()
                .map(baseUrl -> !isCacheCurrent(Vulnerability.Source.TRIVY, apiBaseUrl, packageUrl.getCoordinates()))
                .orElse(false);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void applyAnalysisFromCache(final Component component) {
        getApiBaseUrl().ifPresent(baseUrl ->
                applyAnalysisFromCache(Vulnerability.Source.TRIVY, apiBaseUrl,
                        component.getPurl().getCoordinates(), component, getAnalyzerIdentity(), vulnerabilityAnalysisLevel));
    }

    private void analyzeBlob(final PutRequest blob) {
        if (putBlob(blob)) {
            scanBlob(blob);
            deleteBlob(blob);
        }
    }

    private boolean putBlob(PutRequest input) {
        final String requestUrl = "%s/twirp/trivy.cache.v1.Cache/PutBlob".formatted(apiBaseUrl);

         try {
            URIBuilder uriBuilder = new URIBuilder(requestUrl);
            HttpPost post = new HttpPost(uriBuilder.build().toString());


            Gson gson = new Gson();
            StringEntity body = new StringEntity(gson.toJson(input));
            post.setEntity(body);

            LOGGER.debug("PutBlob request: " + gson.toJson(input));

            HttpUriRequest request = post;

            request.setHeader(HttpHeaders.USER_AGENT, ManagedHttpClientFactory.getUserAgent());
            request.setHeader(TOKEN_HEADER, apiTokenSupplier.get());
            request.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
            try (final CloseableHttpResponse response = RETRY.executeCheckedSupplier(() -> HttpClientPool.getClient().execute(request))) {
                LOGGER.info("PutBlob response: " + response.getStatusLine().getStatusCode());
                return (response.getStatusLine().getStatusCode() >= HttpStatus.SC_OK);
            }
        } catch (Throwable  ex) {
            handleRequestException(LOGGER, ex);
        }
        return false;
    }

    private void scanBlob(PutRequest input) {
        final String requestUrl = "%s/twirp/trivy.scanner.v1.Scanner/Scan".formatted(apiBaseUrl);

         try {
            URIBuilder uriBuilder = new URIBuilder(requestUrl);
            HttpPost post = new HttpPost(uriBuilder.build().toString());

            ScanRequest scan = new ScanRequest();

            scan.setTarget(input.getDiffID());
            scan.setArtifactID(input.getDiffID());
            scan.setBlobIDS(new String[] {input.getDiffID()});

            Options opts = new Options();
            opts.setVulnType(new String[] {"os", "library"});
            opts.setScanners(new String[] {"vuln"});

            scan.setOptions(opts);

            Gson gson = new Gson();
            StringEntity body = new StringEntity(gson.toJson(scan));
            post.setEntity(body);

            LOGGER.debug("Scan request: " + gson.toJson(scan));

            HttpUriRequest request = post;

            request.setHeader(HttpHeaders.USER_AGENT, ManagedHttpClientFactory.getUserAgent());
            request.setHeader(TOKEN_HEADER, apiTokenSupplier.get());
            request.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
            try (final CloseableHttpResponse response = RETRY.executeCheckedSupplier(() -> HttpClientPool.getClient().execute(request))) {


                if (response.getStatusLine().getStatusCode() >= HttpStatus.SC_OK && response.getStatusLine().getStatusCode() < HttpStatus.SC_MULTIPLE_CHOICES) {
                    String responseString = EntityUtils.toString(response.getEntity());
                    var trivyResponse = gson.fromJson(responseString,TrivyResponse.class);

                    LOGGER.info(trivyResponse.toString());
                    // handle(component, responseJson);
                    LOGGER.info("Scan response: " + response.getStatusLine().getStatusCode());
                    LOGGER.debug("Response from server: " + responseString);
                } else if (response.getEntity() != null) {
                    String responseString = EntityUtils.toString(response.getEntity());
                    JSONObject responseJson = new JSONObject(responseString);
                    final List<TrivyError> errors = new TrivyParser().parseErrors(responseJson);
                    if (!errors.isEmpty()) {
                        // LOGGER.error("Analysis of component %s failed with HTTP status %d: \n%s"
                        //         .formatted(component.getPurl(), response.getStatusLine().getStatusCode(), errors.stream()
                        //                 .map(error -> " - %s: %s (%s)" .formatted(error.title(), error.detail(), error.code()))
                        //                 .collect(Collectors.joining("\n"))));
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

    private void deleteBlob(PutRequest input) {
        final String requestUrl = "%s/twirp/trivy.cache.v1.Cache/DeleteBlobs".formatted(apiBaseUrl);

         try {
            URIBuilder uriBuilder = new URIBuilder(requestUrl);
            HttpPost post = new HttpPost(uriBuilder.build().toString());

            DeleteRequest delete = new DeleteRequest();
            delete.setBlobIDS(new String[] {input.getDiffID()});

            Gson gson = new Gson();

            StringEntity body = new StringEntity(gson.toJson(delete));
            post.setEntity(body);

            LOGGER.debug("Delete Request: " + gson.toJson(delete));

            HttpUriRequest request = post;

            request.setHeader(HttpHeaders.USER_AGENT, ManagedHttpClientFactory.getUserAgent());
            request.setHeader(TOKEN_HEADER, apiTokenSupplier.get());
            request.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
            final CloseableHttpResponse response = RETRY.executeCheckedSupplier(() -> HttpClientPool.getClient().execute(request));
            LOGGER.info("DeleteBlob response: " + response.getStatusLine().getStatusCode());
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
                final var trivyParser = new TrivyParser();
                for (int count = 0; count < data.length(); count++) {
                    Vulnerability synchronizedVulnerability = trivyParser.parse(data, qm, purl, count, true);
                    addVulnerabilityToCache(component, synchronizedVulnerability);
                    final Component componentPersisted = qm.getObjectByUuid(Component.class, component.getUuid());
                    if (componentPersisted != null && synchronizedVulnerability.getVulnId() != null) {
                        NotificationUtil.analyzeNotificationCriteria(qm, synchronizedVulnerability, componentPersisted, vulnerabilityAnalysisLevel);
                        qm.addVulnerability(synchronizedVulnerability, componentPersisted, this.getAnalyzerIdentity());
                        LOGGER.debug("Trivy vulnerability added : " + synchronizedVulnerability.getVulnId() + " to component " + component.getName());
                    }
                    Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
                }
            } else {
                addNoVulnerabilityToCache(component);
            }
            updateAnalysisCacheStats(qm, Vulnerability.Source.TRIVY, apiBaseUrl, component.getPurl().getCoordinates(), component.getCacheResult());
        }
    }

    private Optional<String> getApiBaseUrl() {
        if (apiBaseUrl != null) {
            return Optional.of(apiBaseUrl);
        }

        try (final var qm = new QueryManager()) {
            final ConfigProperty property = qm.getConfigProperty(
                    ConfigPropertyConstants.SCANNER_TRIVY_BASE_URL.getGroupName(),
                    ConfigPropertyConstants.SCANNER_TRIVY_BASE_URL.getPropertyName()
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
